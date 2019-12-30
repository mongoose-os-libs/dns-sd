/*
 * Copyright (c) 2014-2018 Cesanta Software Limited
 * All rights reserved
 *
 * Licensed under the Apache License, Version 2.0 (the ""License"");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an ""AS IS"" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Configuration setting:   dns_sd.host_name=my_host
 * DNS-SD service_name:     my_host._http._tcp.local
 * DNS-SD host_name:        my_host.local
 */

#include "mgos_dns_sd.h"

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>

#include "mgos_http_server.h"

#include "common/cs_dbg.h"
#include "common/platform.h"
#include "common/queue.h"
#include "mgos_mdns_internal.h"
#include "mgos_mongoose.h"
#include "mgos_net.h"
#include "mgos_ro_vars.h"
#include "mgos_sys_config.h"
#include "mgos_timers.h"
#include "mongoose.h"
#ifdef MGOS_HAVE_WIFI
#include "mgos_wifi.h"
#endif

#define SD_DOMAIN "local"
#define MGOS_MDNS_QUERY_UNICAST 0x8000
#define MGOS_MDNS_CACHE_FLUSH 0x8000
#define RCLASS_IN_NOFLUSH 0x0001
#define RCLASS_IN_FLUSH 0x8001
#define SD_TYPE_ENUM_NAME "_services._dns-sd._udp." SD_DOMAIN

struct mgos_dns_sd_service_entry {
  struct mg_str name; /* full name, instance.proto.domain */
  int port;
  struct mg_str txt;
  SLIST_ENTRY(mgos_dns_sd_service_entry) next;
  // This field is used to keep track of which records have already been
  // included in the response. It is a hack: this field is a per-response bit of
  // state and does not belong here. But as long as we can't have more than one
  // response in preparation, it's fine.
  uint8_t flags;
};

// Flags fields.
#define F_PTR_SENT (1 << 0)
#define F_SRV_SENT (1 << 1)
#define F_TXT_SENT (1 << 2)

static struct mg_str s_host_name = MG_NULL_STR;
SLIST_HEAD(s_instances, mgos_dns_sd_service_entry) s_instances;

static void reset_flags(void) {
  struct mgos_dns_sd_service_entry *e = NULL;
  SLIST_FOREACH(e, &s_instances, next) {
    e->flags = 0;
  }
}

static struct mg_dns_resource_record make_dns_rr(int type, uint16_t rclass,
                                                 int ttl) {
  struct mg_dns_resource_record rr = {
      .name = MG_NULL_STR,
      .rtype = type,
      .rclass = rclass,
      .ttl = ttl,
      .kind = MG_DNS_ANSWER,
  };
  return rr;
}

static void add_srv_record(struct mg_dns_reply *reply, struct mg_str name,
                           struct mg_str host, int port, int ttl,
                           struct mbuf *rdata) {
  /* prio 0, weight 0 */
  char rdata_header[] = {0x0, 0x0, 0x0, 0x0};
  struct mg_dns_resource_record rr =
      make_dns_rr(MG_DNS_SRV_RECORD, RCLASS_IN_FLUSH, ttl);
  uint16_t port16 = htons(port);
  rdata->len = 0;
  mbuf_append(rdata, rdata_header, sizeof(rdata_header));
  mbuf_append(rdata, &port16, sizeof(port16));
  mg_dns_encode_name_s(rdata, host);
  mg_dns_encode_record(reply->io, &rr, name.p, name.len, rdata->buf,
                       rdata->len);
  LOG(LL_DEBUG, ("    %d: %.*s SRV %d %.*s:%d", reply->msg->num_answers,
                 (int) name.len, name.p, ttl, (int) host.len, host.p, port));
  reply->msg->num_answers++;
}

// This record contains negative answer for the IPv6 AAAA question
static void add_nsec_record(struct mg_dns_reply *reply, struct mg_str name,
                            bool naive_client, int ttl, struct mbuf *rdata) {
  struct mg_dns_resource_record rr =
      make_dns_rr(MG_DNS_NSEC_RECORD,
                  (naive_client ? RCLASS_IN_NOFLUSH : RCLASS_IN_FLUSH), ttl);
  rdata->len = 0;
  mg_dns_encode_name_s(rdata, name);
  mbuf_append(rdata, "\x00\x01\x40", 3); /* Only A record is present */
  mg_dns_encode_record(reply->io, &rr, name.p, name.len, rdata->buf,
                       rdata->len);
  LOG(LL_DEBUG, ("    %d: %.*s NSEC %d", reply->msg->num_answers,
                 (int) name.len, name.p, ttl));
  reply->msg->num_answers++;
}

static void add_a_record(struct mg_dns_reply *reply, struct mg_str name,
                         bool naive_client, int ttl, struct mbuf *rdata) {
  uint32_t addr = 0;
  struct mgos_net_ip_info ip_info;
#ifdef MGOS_HAVE_WIFI
  if (mgos_net_get_ip_info(MGOS_NET_IF_TYPE_WIFI, MGOS_NET_IF_WIFI_STA,
                           &ip_info)) {
    addr = ip_info.ip.sin_addr.s_addr;
  } else if (mgos_net_get_ip_info(MGOS_NET_IF_TYPE_WIFI, MGOS_NET_IF_WIFI_AP,
                                  &ip_info)) {
    addr = ip_info.ip.sin_addr.s_addr;
  }
#else
  (void) ip_info;
#endif
  if (addr != 0) {
    struct mg_dns_resource_record rr =
        make_dns_rr(MG_DNS_A_RECORD,
                    (naive_client ? RCLASS_IN_NOFLUSH : RCLASS_IN_FLUSH), ttl);
    mg_dns_encode_record(reply->io, &rr, name.p, name.len, &addr, sizeof(addr));
    LOG(LL_DEBUG, ("    %d: %.*s A %d %08x", reply->msg->num_answers,
                   (int) name.len, name.p, ttl, (unsigned int) addr));
    reply->msg->num_answers++;
  }
  (void) rdata;
}

static void add_txt_record(struct mg_dns_reply *reply, struct mg_str name,
                           struct mg_str txt, int ttl, struct mbuf *rdata) {
  struct mg_dns_resource_record rr =
      make_dns_rr(MG_DNS_TXT_RECORD, RCLASS_IN_FLUSH, ttl);
  mg_dns_encode_record(reply->io, &rr, name.p, name.len, txt.p, txt.len);
  LOG(LL_DEBUG, ("    %d: %.*s TXT %d %.*s", reply->msg->num_answers,
                 (int) name.len, name.p, ttl, (int) txt.len, txt.p));
  reply->msg->num_answers++;
  (void) rdata;
}

static void add_ptr_record(struct mg_dns_reply *reply, struct mg_str name,
                           struct mg_str target, int ttl, struct mbuf *rdata) {
  struct mg_dns_resource_record rr =
      make_dns_rr(MG_DNS_PTR_RECORD, RCLASS_IN_NOFLUSH, ttl);
  rdata->len = 0;
  LOG(LL_DEBUG, ("    %d: %.*s PTR %d %.*s", reply->msg->num_answers,
                 (int) name.len, name.p, ttl, (int) target.len, target.p));
  mg_dns_encode_name_s(rdata, target);
  mg_dns_encode_record(reply->io, &rr, name.p, name.len, rdata->buf,
                       rdata->len);
  reply->msg->num_answers++;
}

static struct mg_str get_service(struct mg_str name) {
  const char *p = mg_strchr(name, '.') + 1;
  return mg_mk_str_n(p, (name.p + name.len) - p);
}

static void add_service_records(struct mg_dns_reply *reply, int ttl,
                                struct mbuf *rdata) {
  struct mgos_dns_sd_service_entry *e1 = NULL;
  SLIST_FOREACH(e1, &s_instances, next) {
    bool found = false;
    const struct mgos_dns_sd_service_entry *e2 = NULL;
    const struct mg_str e1_service = get_service(e1->name);
    SLIST_FOREACH(e2, &s_instances, next) {
      if (e2 == e1) break;
      const struct mg_str e2_service = get_service(e2->name);
      if (mg_strcasecmp(e1_service, e2_service) == 0) {
        found = true;
        break;
      }
    }
    if (!found) {
      add_ptr_record(reply, mg_mk_str(SD_TYPE_ENUM_NAME), e1_service, ttl,
                     rdata);
    }
  }
}

static void add_instance_records(struct mg_dns_reply *reply,
                                 struct mgos_dns_sd_service_entry *e, bool ptr,
                                 bool srv, bool txt, int ttl,
                                 struct mbuf *rdata) {
  const struct mg_str e_service = get_service(e->name);
  /* service PTR instance */
  if (ptr && !(e->flags & F_PTR_SENT)) {
    add_ptr_record(reply, e_service, e->name, ttl, rdata);
    e->flags |= F_PTR_SENT;
  }
  /* instance SRV host */
  if (srv && !(e->flags & F_SRV_SENT)) {
    add_srv_record(reply, e->name, s_host_name, e->port, ttl, rdata);
    e->flags |= F_SRV_SENT;
  }
  /* instance TXT txt */
  if (txt && !(e->flags & F_TXT_SENT)) {
    add_txt_record(reply, e->name, e->txt, ttl, rdata);
    e->flags |= F_TXT_SENT;
  }
}

static void advertise(struct mg_dns_reply *reply, bool naive_client, int ttl,
                      struct mbuf *rdata) {
  add_service_records(reply, ttl, rdata);
  struct mgos_dns_sd_service_entry *e = NULL;
  SLIST_FOREACH(e, &s_instances, next) {
    add_instance_records(reply, e, true, true, true, ttl, rdata);
  }
  /* host A ip */
  add_a_record(reply, s_host_name, naive_client, ttl, rdata);
  add_nsec_record(reply, s_host_name, naive_client, ttl, rdata);
}

static void handler(struct mg_connection *nc, int ev, void *ev_data,
                    void *user_data) {
  if (!mgos_sys_config_get_dns_sd_enable()) return;

  switch (ev) {
    case MG_DNS_MESSAGE: {
      int i;
      struct mg_dns_message *msg = (struct mg_dns_message *) ev_data;
      struct mg_dns_reply reply;
      struct mbuf rdata;
      struct mbuf reply_mbuf;
      /* the reply goes either to the sender or to a multicast dest */
      struct mg_connection *reply_conn = nc;
      char *peer = inet_ntoa(nc->sa.sin.sin_addr);
      int ttl = mgos_sys_config_get_dns_sd_ttl();
      LOG(LL_DEBUG, ("-- DNS packet from %s (%d questions, %d answers)", peer,
                     msg->num_questions, msg->num_answers));
      mbuf_init(&rdata, 0);
      mbuf_init(&reply_mbuf, 512);
      int tmp = msg->num_questions;
      msg->num_questions = 0;
      reply = mg_dns_create_reply(&reply_mbuf, msg);
      msg->num_questions = tmp;
      reset_flags();
      bool need_a = false, have_a = false;
      /* Additional heuristic: multicast queries should use ID of 0.
       * If ID is not 0, we take it to indicate a naive client trying to
       * use multicast address for queries, i.e. dig @224.0.0.251 */
      bool naive_client = (msg->transaction_id != 0);

      for (i = 0; i < msg->num_questions; i++) {
        char name_buf[256];
        struct mg_dns_resource_record *rr = &msg->questions[i];
        mg_dns_uncompress_name(msg, &rr->name, name_buf, sizeof(name_buf) - 1);
        struct mg_str name = mg_mk_str(name_buf);
        int is_unicast = (rr->rclass & MGOS_MDNS_QUERY_UNICAST) || naive_client;

        LOG(LL_DEBUG, ("  Q type %d name %.*s (%s), unicast: %d", rr->rtype,
                       (int) name.len, name.p, (is_unicast ? "QU" : "QM"),
                       (rr->rclass & MGOS_MDNS_QUERY_UNICAST) != 0));
        /*
         * If there is at least one question that requires a multicast answer
         * the whole reply goes to a multicast destination
         */
        if (!is_unicast) {
          /* our listener connection has the mcast address in its nc->sa */
          reply_conn = nc->listener;
        }
        /*
         * MSB in rclass is used to mean QU/QM in queries and cache flush in
         * reply. Set cache flush bit by default; enumeration replies will
         * remove it as needed.
         */
        rr->rclass |= MGOS_MDNS_CACHE_FLUSH;

        if (rr->rtype == MG_DNS_PTR_RECORD &&
            mg_strcasecmp(name, mg_mk_str(SD_TYPE_ENUM_NAME)) == 0) {
          advertise(&reply, naive_client, mgos_sys_config_get_dns_sd_ttl(),
                    &rdata);
          have_a = true;
        } else if ((rr->rtype == MG_DNS_A_RECORD ||
                    rr->rtype == MG_DNS_AAAA_RECORD) &&
                   mg_strcasecmp(name, s_host_name) == 0) {
          need_a = true;
        } else {
          struct mgos_dns_sd_service_entry *e = NULL;
          SLIST_FOREACH(e, &s_instances, next) {
            if (mg_strcasecmp(name, e->name) == 0) {
              bool need_srv = (rr->rtype == MG_DNS_SRV_RECORD);
              bool need_txt = (rr->rtype == MG_DNS_TXT_RECORD);
              add_instance_records(&reply, e, false, need_srv, need_txt, ttl,
                                   &rdata);
              need_a = true;
            } else if (rr->rtype == MG_DNS_PTR_RECORD) {
              struct mg_str e_service = get_service(e->name);
              if (mg_strcasecmp(name, e_service) == 0) {
                add_instance_records(&reply, e, true, true, true, ttl, &rdata);
                need_a = true;
              }
            }
          }
        }
      }
      if (need_a && !have_a) {
        add_a_record(&reply, s_host_name, naive_client, ttl, &rdata);
        add_nsec_record(&reply, s_host_name, naive_client, ttl, &rdata);
      }

      if (msg->num_answers > 0) {
        LOG(LL_DEBUG, ("  %c %d answers, %s, size %d",
                       (reply.msg->num_answers > 0 ? '+' : '-'),
                       (int) reply.msg->num_answers,
                       (reply_conn == nc ? "unicast" : "multicast"),
                       (int) reply.io->len));
        msg->num_questions = 0;
        msg->flags = 0x8400; /* Authoritative answer */
        mg_dns_send_reply(reply_conn, &reply);
      }
      mbuf_free(&rdata);
      mbuf_free(&reply_mbuf);
      break;
    }
  }

  (void) user_data;
}

static void dns_sd_advertise(struct mg_connection *c, int ttl) {
  struct mbuf mbuf1, mbuf2;
  struct mg_dns_message msg;
  struct mg_dns_reply reply;
  LOG(LL_DEBUG, ("advertising, ttl=%d", ttl));
  mbuf_init(&mbuf1, 0);
  mbuf_init(&mbuf2, 0);
  memset(&msg, 0, sizeof(msg));
  msg.flags = 0x8400;
  reply = mg_dns_create_reply(&mbuf1, &msg);
  reset_flags();
  advertise(&reply, false /* naive_client */, ttl, &mbuf2);
  if (msg.num_answers > 0) {
    LOG(LL_DEBUG, ("sending adv as M, size %d", (int) reply.io->len));
    mg_dns_send_reply(c, &reply);
  }
  mbuf_free(&mbuf1);
  mbuf_free(&mbuf2);
}

static void dns_sd_adv_timer_cb(void *arg) {
  mgos_dns_sd_advertise();
  (void) arg;
}

static void dns_sd_net_ev_handler(int ev, void *evd, void *arg) {
  struct mg_connection *c = mgos_mdns_get_listener();
  LOG(LL_DEBUG, ("ev %d, data %p, mdns_listener %p", ev, arg, c));
  if (ev == MGOS_NET_EV_IP_ACQUIRED && c != NULL) {
    mgos_dns_sd_advertise();
    mgos_set_timer(1000, 0, dns_sd_adv_timer_cb, NULL); /* By RFC, repeat */
  }
  (void) evd;
}

const char *mgos_dns_sd_get_host_name(void) {
  return s_host_name.p;
}

void mgos_dns_sd_advertise(void) {
  struct mg_connection *c = mgos_mdns_get_listener();
  if (c != NULL) dns_sd_advertise(c, mgos_sys_config_get_dns_sd_ttl());
}

void mgos_dns_sd_goodbye(void) {
  struct mg_connection *c = mgos_mdns_get_listener();
  if (c != NULL) dns_sd_advertise(c, 0);
}

static void mgos_dns_sd_service_entry_free(
    struct mgos_dns_sd_service_entry *e) {
  if (e == NULL) return;
  mg_strfree(&e->name);
  mg_strfree(&e->txt);
  free(e);
}

bool mgos_dns_sd_add_service_instance(
    const char *instance, const char *proto, int port,
    const struct mgos_dns_sd_txt_entry *txt_entries) {
  char buf[256] = {0}, *p = buf;
  struct mgos_dns_sd_service_entry *e = NULL;
  bool res = false, is_new = false;
  int name_len =
      snprintf(buf, sizeof(buf) - 1, "%s.%s.%s", instance, proto, SD_DOMAIN);
  struct mg_str name = MG_MK_STR_N(buf, name_len);

  const struct mgos_dns_sd_txt_entry *te;
  SLIST_FOREACH(e, &s_instances, next) {
    if (e->port == port && mg_strcasecmp(e->name, name) == 0) break;
  };
  if (e == NULL) {
    e = (struct mgos_dns_sd_service_entry *) calloc(1, sizeof(*e));
    if (e == NULL) goto out;
    e->name = mg_strdup(name);
    e->port = port;
    if (e->name.p == NULL) goto out;
    is_new = true;
  }
  for (te = txt_entries; te != NULL && te->key != NULL; te++) {
    if (te->value == NULL) continue;
    int p_size = sizeof(buf) - (p - buf) - 1;
    if (p_size <= 0) goto out;
    uint8_t len = snprintf(p + 1, p_size, "%s=%s", te->key, te->value);
    *p = len;
    p += len + 1;
  }
  const struct mg_str txt = MG_MK_STR_N(buf, p - buf);
  mg_strfree(&e->txt);
  e->txt = mg_strdup(txt);
  res = (e->txt.len == txt.len);

out:
  if (is_new) {
    if (res) {
      SLIST_INSERT_HEAD(&s_instances, e, next);
    } else {
      mgos_dns_sd_service_entry_free(e);
    }
  }
  if (res) {
    mgos_dns_sd_advertise();
  }
  return res;
}

/* Initialize the DNS-SD subsystem */
bool mgos_dns_sd_init(void) {
  if (!mgos_sys_config_get_dns_sd_enable()) return true;
#ifdef MGOS_HAVE_WIFI
  if (mgos_sys_config_get_wifi_ap_enable() &&
      mgos_sys_config_get_wifi_sta_enable()) {
    /* Reason: multiple interfaces. More work is required to make sure
     * requests and responses are correctly plumbed to the right interface. */
    LOG(LL_ERROR, ("MDNS does not work in AP+STA mode"));
    return true;
  }
#endif
  if (!mgos_sys_config_get_http_enable()) {
    LOG(LL_ERROR, ("MDNS wants HTTP enabled"));
    return true;
  }
  if (!mgos_mdns_init()) return false;
  mgos_mdns_add_handler(handler, NULL);
  mgos_event_add_group_handler(MGOS_EVENT_GRP_NET, dns_sd_net_ev_handler, NULL);
  mgos_set_timer(mgos_sys_config_get_dns_sd_ttl() * 1000 / 2 + 1,
                 MGOS_TIMER_REPEAT, dns_sd_adv_timer_cb, NULL);
  const char *hn = mgos_sys_config_get_dns_sd_host_name();
  if (hn == NULL) {
    hn = mgos_sys_config_get_device_id();
  }
  if (hn == NULL) {
    LOG(LL_ERROR, ("dns_sd.host_name and device.id are not set"));
    return false;
  }
  s_host_name.len =
      mg_asprintf((char **) &s_host_name.p, 0, "%s.%s", hn, SD_DOMAIN);
  mgos_expand_mac_address_placeholders((char *) s_host_name.p);
  for (size_t i = 0; i < s_host_name.len - sizeof(SD_DOMAIN); i++) {
    if (!isalnum((int) s_host_name.p[i])) ((char *) s_host_name.p)[i] = '-';
  }
#ifdef MGOS_HAVE_HTTP_SERVER
  struct mg_connection *lc = mgos_get_sys_http_server();
  if (lc != NULL) {
    int n = 0;
    struct mgos_dns_sd_txt_entry *txt = NULL;
#if !MGOS_DNS_SD_HIDE_ADDITIONAL_INFO
    const struct mgos_dns_sd_txt_entry txt_id = {
        .key = "id",
        .value = mgos_sys_config_get_device_id(),
    };
    const struct mgos_dns_sd_txt_entry txt_fw_id = {
        .key = "fw_id",
        .value = mgos_sys_ro_vars_get_fw_id(),
    };
    const struct mgos_dns_sd_txt_entry txt_arch = {
        .key = "arch",
        .value = mgos_sys_ro_vars_get_arch(),
    };
    txt = realloc(txt, (n + 4) * sizeof(*txt));
    if (txt == NULL) return false;
    txt[0] = txt_id;
    txt[1] = txt_fw_id;
    txt[2] = txt_arch;
    n += 3;
#endif
    // Append extra labels from config.
    char *extra_txt = NULL;
    if (mgos_sys_config_get_dns_sd_txt() != NULL) {
      extra_txt = strdup(mgos_sys_config_get_dns_sd_txt());
      const char *p = extra_txt;
      struct mg_str key, val;
      while ((p = mg_next_comma_list_entry(p, &key, &val)) != NULL) {
        ((char *) key.p)[key.len] = '\0';
        ((char *) val.p)[val.len] = '\0';
        txt = realloc(txt, (n + 2) * sizeof(*txt));
        if (txt == NULL) return false;
        txt[n].key = key.p;
        txt[n].value = val.p;
        n++;
      }
    }
    if (txt != NULL) txt[n].key = NULL;
    // Use instance = host name.
    const char *p = mg_strchr(s_host_name, '.');
    struct mg_str inst =
        mg_strdup_nul(mg_mk_str_n(s_host_name.p, p - s_host_name.p));
    mgos_dns_sd_add_service_instance(inst.p, "_http._tcp",
                                     ntohs(lc->sa.sin.sin_port), txt);
    mg_strfree(&inst);
    free(extra_txt);
    free(txt);
  }
#endif /* MGOS_HAVE_HTTP_SERVER */
  LOG(LL_INFO, ("MDNS initialized, host %.*s, ttl %d", (int) s_host_name.len,
                s_host_name.p, mgos_sys_config_get_dns_sd_ttl()));
  return true;
}
