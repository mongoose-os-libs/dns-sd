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

#include "common/cs_dbg.h"
#include "common/platform.h"
#include "common/queue.h"
#include "mgos_mdns_internal.h"
#include "mgos_mongoose.h"
#include "mgos_net.h"
#include "mgos_sys_config.h"
#include "mgos_system.h"
#include "mgos_timers.h"
#include "mgos_utils.h"
#ifdef MGOS_HAVE_WIFI
#include "mgos_wifi.h"
#endif

#include "mongoose.h"

#define TTL_SHORT 2 * 60
#define TTL_LONG 75 * 60

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
                         uint32_t addr, bool naive_client, int ttl,
                         struct mbuf *rdata) {
  if (addr == 0) return;
  struct mg_dns_resource_record rr =
      make_dns_rr(MG_DNS_A_RECORD,
                  (naive_client ? RCLASS_IN_NOFLUSH : RCLASS_IN_FLUSH), ttl);
  mg_dns_encode_record(reply->io, &rr, name.p, name.len, &addr, sizeof(addr));
  LOG(LL_DEBUG, ("    %d: %.*s A %d %s", reply->msg->num_answers,
                 (int) name.len, name.p, ttl, inet_ntoa(addr)));
  reply->msg->num_answers++;
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

static void add_service_records(struct mg_dns_reply *reply, bool goodbye,
                                struct mbuf *rdata) {
  int ttl = (goodbye ? 0 : TTL_LONG);
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
                                 bool srv, bool txt, bool goodbye,
                                 struct mbuf *rdata) {
  const struct mg_str e_service = get_service(e->name);
  int ttl_short = (goodbye ? 0 : TTL_SHORT);
  /* service PTR instance */
  if (ptr && !(e->flags & F_PTR_SENT)) {
    add_ptr_record(reply, e_service, e->name, (goodbye ? 0 : TTL_LONG), rdata);
    e->flags |= F_PTR_SENT;
  }
  /* instance SRV host */
  if (srv && !(e->flags & F_SRV_SENT)) {
    add_srv_record(reply, e->name, s_host_name, e->port, ttl_short, rdata);
    e->flags |= F_SRV_SENT;
  }
  /* instance TXT txt */
  if (txt && !(e->flags & F_TXT_SENT)) {
    add_txt_record(reply, e->name, e->txt, ttl_short, rdata);
    e->flags |= F_TXT_SENT;
  }
}

static void advertise(struct mg_dns_reply *reply, uint32_t ip_addr,
                      bool naive_client, bool goodbye, struct mbuf *rdata) {
  add_service_records(reply, goodbye, rdata);
  struct mgos_dns_sd_service_entry *e = NULL;
  SLIST_FOREACH(e, &s_instances, next) {
    add_instance_records(reply, e, true, true, true, goodbye, rdata);
  }
  /* host A ip */
  int ttl = (goodbye ? 0 : TTL_SHORT);
  add_a_record(reply, s_host_name, ip_addr, naive_client, ttl, rdata);
  add_nsec_record(reply, s_host_name, naive_client, ttl, rdata);
}

static void dns_sd_advertise_if(enum mgos_net_if_type if_type, int if_instance,
                                bool goodbye);

static void dns_sd_adv_repeat_timer_cb(void *arg) {
  uintptr_t x = (uintptr_t) arg;
  enum mgos_net_if_type if_type = (enum mgos_net_if_type)(x >> 16);
  int if_instance = (int) (x & 0xffff);
  dns_sd_advertise_if(if_type, if_instance, false /* goodbye */);
}

static void handler(struct mg_connection *nc, int ev, void *ev_data,
                    void *user_data) {
  if (!mgos_sys_config_get_dns_sd_enable()) return;
  const struct mgos_mdns_message *mm = (struct mgos_mdns_message *) ev_data;

  switch (ev) {
    case MG_EV_CONNECT: {
      dns_sd_advertise_if(mm->if_type, mm->if_instance, false /* goodbye */);
      // Repeat after 1 second, per standard.
      uintptr_t arg = (((uintptr_t) mm->if_type) << 16) | mm->if_instance;
      mgos_set_timer(1000, 0, dns_sd_adv_repeat_timer_cb, (void *) arg);
      break;
    }
    case MGOS_EV_MDNS_MESSAGE: {
      int i;
      struct mg_dns_message *msg = mm->dns_msg;
      struct mg_dns_reply reply;
      struct mbuf rdata;
      struct mbuf reply_mbuf;
      /* the reply goes either to the sender or to a multicast dest */
      struct mg_connection *reply_conn = nc;
      char *peer = inet_ntoa(nc->sa.sin.sin_addr);
      LOG(LL_DEBUG, ("-- %d.%d DNS packet from %s (%d questions, %d answers)",
                     mm->if_type, mm->if_instance, peer, msg->num_questions,
                     msg->num_answers));
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

      /* HACK: Passed from LWIP netif */
      const uint32_t local_addr = (uint32_t)(uintptr_t) nc->priv_2;

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
          advertise(&reply, local_addr, naive_client, false /* goodbye */,
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
              add_instance_records(&reply, e, false, need_srv, need_txt,
                                   false /* goodbye */, &rdata);
              need_a = true;
            } else if (rr->rtype == MG_DNS_PTR_RECORD) {
              struct mg_str e_service = get_service(e->name);
              if (mg_strcasecmp(name, e_service) == 0) {
                add_instance_records(&reply, e, true, true, true,
                                     false /* goodbye */, &rdata);
                need_a = true;
              }
            }
          }
        }
      }
      if (need_a && !have_a) {
        if (local_addr != 0) {
          add_a_record(&reply, s_host_name, local_addr, naive_client, TTL_SHORT,
                       &rdata);
          add_nsec_record(&reply, s_host_name, naive_client, TTL_SHORT, &rdata);
        } else {
          LOG(LL_ERROR, ("Local interface address not recorded!"));
        }
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
      (void) peer;
      break;
    }
  }

  (void) user_data;
}

static void dns_sd_advertise_if(enum mgos_net_if_type if_type, int if_instance,
                                bool goodbye) {
  struct mgos_net_ip_info ip_info;
  if (!mgos_net_get_ip_info(if_type, if_instance, &ip_info)) return;
  struct mbuf mbuf1, mbuf2;
  struct mg_dns_message msg;
  struct mg_dns_reply reply;
  mbuf_init(&mbuf1, 0);
  mbuf_init(&mbuf2, 0);
  memset(&msg, 0, sizeof(msg));
  msg.flags = 0x8400;
  reply = mg_dns_create_reply(&mbuf1, &msg);
  reset_flags();
  advertise(&reply, ip_info.ip.sin_addr.s_addr, false /* naive_client */,
            goodbye, &mbuf2);
  if (msg.num_answers > 0) {
    LOG(LL_DEBUG, ("%d.%d sending adv as M, size %d, goodbye %d", if_type,
                   if_instance, (int) reply.io->len, goodbye));
    mg_dns_insert_header(reply.io, reply.start, reply.msg);
    mgos_mdns_advertise(if_type, if_instance, &mbuf1);
  }
  mbuf_free(&mbuf1);
  mbuf_free(&mbuf2);
}

static void dns_sd_advertise(bool goodbye) {
#ifdef MGOS_HAVE_WIFI
  dns_sd_advertise_if(MGOS_NET_IF_TYPE_WIFI, MGOS_NET_IF_WIFI_STA, goodbye);
  dns_sd_advertise_if(MGOS_NET_IF_TYPE_WIFI, MGOS_NET_IF_WIFI_AP, goodbye);
#endif
#ifdef MGOS_HAVE_ETHERNET
  dns_sd_advertise_if(MGOS_NET_IF_TYPE_ETHERNET, 0, goodbye);
#endif
}

static void dns_sd_adv_timer_cb(void *arg) {
  dns_sd_advertise(false /* goodbye */);
  (void) arg;
}

const char *mgos_dns_sd_get_host_name(void) {
  return s_host_name.p;
}

// dns_sd_advertise uses a lot of stack, so it's run via invoke_cb.
static void mgos_dns_sd_advertise2(void *arg) {
  bool goodbye = (bool) (intptr_t) arg;
  dns_sd_advertise(goodbye);
}

void mgos_dns_sd_advertise(void) {
  mgos_invoke_cb(mgos_dns_sd_advertise2, (void *) 0, false /* from_isr */);
}

void mgos_dns_sd_goodbye(void) {
  mgos_invoke_cb(mgos_dns_sd_advertise2, (void *) 1, false /* from_isr */);
}

static void mgos_dns_sd_service_entry_free(
    struct mgos_dns_sd_service_entry *e) {
  if (e == NULL) return;
  mg_strfree(&e->name);
  mg_strfree(&e->txt);
  free(e);
}

bool mgos_dns_sd_add_service_instance(
    const char *name, const char *proto, int port,
    const struct mgos_dns_sd_txt_entry *txt_entries) {
  char buf[256] = {0}, *p = buf;
  struct mgos_dns_sd_service_entry *e = NULL;
  bool res = false, is_new = false;
  int fqdn_len =
      snprintf(buf, sizeof(buf) - 1, "%s.%s.%s", name, proto, SD_DOMAIN);
  struct mg_str fqdn = MG_MK_STR_N(buf, fqdn_len);

  const struct mgos_dns_sd_txt_entry *te;
  SLIST_FOREACH(e, &s_instances, next) {
    if (e->port == port && mg_strcasecmp(e->name, fqdn) == 0) break;
  };
  if (e == NULL) {
    e = (struct mgos_dns_sd_service_entry *) calloc(1, sizeof(*e));
    if (e == NULL) goto out;
    e->name = mg_strdup(fqdn);
    e->port = port;
    if (e->name.p == NULL) goto out;
    is_new = true;
  }
  for (te = txt_entries; te != NULL && te->key != NULL; te++) {
    int p_size = sizeof(buf) - (p - buf) - 1;
    if (p_size <= 0) goto out;
    uint8_t len = snprintf(p + 1, p_size, "%s=%.*s", te->key,
                           (int) te->value.len, te->value.p);
    *p = len;
    p += len + 1;
  }
  const struct mg_str txt = MG_MK_STR_N(buf, p - buf);
  mg_strfree(&e->txt);
  e->txt = mg_strdup_nul(txt);
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

bool mgos_dns_sd_remove_service_instance(const char *name, const char *proto,
                                         int port) {
  char buf[256] = {0};
  int fqdn_len =
      snprintf(buf, sizeof(buf) - 1, "%s.%s.%s", name, proto, SD_DOMAIN);
  struct mg_str fqdn = MG_MK_STR_N(buf, fqdn_len);

  struct mgos_dns_sd_service_entry *e;
  SLIST_FOREACH(e, &s_instances, next) {
    if (e->port == port && mg_strcasecmp(e->name, fqdn) == 0) break;
  };
  if (e == NULL) return false;
  SLIST_REMOVE(&s_instances, e, mgos_dns_sd_service_entry, next);
  // TODO: Send a good-bye packet for the associated records.
  mgos_dns_sd_service_entry_free(e);
  return true;
}

bool mgos_dns_sd_set_host_name(const char *name) {
  if (name == NULL) {
    name = mgos_sys_config_get_dns_sd_host_name();
    if (name == NULL) {
      name = mgos_sys_config_get_device_id();
    }
  }
  if (name == NULL) {
    return false;
  }
  bool adv = false;
  if (s_host_name.len > 0) {
    mgos_dns_sd_goodbye();
    mg_strfree(&s_host_name);
    adv = true;
  }
  s_host_name.len =
      mg_asprintf((char **) &s_host_name.p, 0, "%s.%s", name, SD_DOMAIN);
  mgos_expand_mac_address_placeholders((char *) s_host_name.p);
  for (size_t i = 0; i < s_host_name.len - sizeof(SD_DOMAIN); i++) {
    if (!isalnum((int) s_host_name.p[i])) ((char *) s_host_name.p)[i] = '-';
  }
  if (adv) {
    mgos_dns_sd_advertise();
  }
  return true;
}

/* Initialize the DNS-SD subsystem */
bool mgos_dns_sd_init(void) {
  if (!mgos_sys_config_get_dns_sd_enable()) return true;
  if (!mgos_mdns_init()) return false;
  mgos_mdns_add_handler(handler, NULL);
  int intvl_base = TTL_SHORT * 1000 / 4;
  int adv_intvl = mgos_rand_range(intvl_base * 0.9f, intvl_base);
  mgos_set_timer(adv_intvl, MGOS_TIMER_REPEAT, dns_sd_adv_timer_cb, NULL);

  if (!mgos_dns_sd_set_host_name(NULL)) {
    return false;
  }

  LOG(LL_INFO, ("DNS-SD initialized, host %.*s, adv intvl %d",
                (int) s_host_name.len, s_host_name.p, adv_intvl));
  return true;
}
