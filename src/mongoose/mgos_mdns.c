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

#include "mgos_mdns_internal.h"

#include <stdlib.h>

#include "common/cs_dbg.h"
#include "common/platform.h"
#include "common/queue.h"

#include "mgos_mongoose.h"
#include "mgos_net.h"
#include "mgos_sys_config.h"

#ifdef MGOS_HAVE_WIFI
#include "mgos_wifi.h"
#endif

#define MDNS_MCAST_GROUP "224.0.0.251"
#define MDNS_LISTENER_SPEC "udp://:5353"

struct mdns_handler {
  mg_event_handler_t handler;
  void *ud;
  SLIST_ENTRY(mdns_handler) next;
};

struct mdns_interface {
  enum mgos_net_if_type if_type;
  bool connected;
  int if_instance;
  struct sockaddr_in local_ip4;
  struct mbuf pending;
  SLIST_ENTRY(mdns_interface) next;
};

struct mg_connection *s_mdns_listener = NULL;

SLIST_HEAD(mdns_handlers, mdns_handler) s_mdns_handlers;
SLIST_HEAD(mdns_interfaces, mdns_interface) s_mdns_interfaces;

static void sock_ev_handler(struct mg_connection *nc, int ev, void *ev_data,
                            void *user_data) {
  switch (ev) {
    case MG_DNS_MESSAGE: {
      struct mdns_handler *e = NULL;
      // Hack: populated by mg_lwip_if.
      uint32_t local_ip4 = (uint32_t)(uintptr_t) nc->priv_2;
      if (local_ip4 == 0) {
        LOG(LL_DEBUG, ("Local IP not populated!"));
        return;
      }
      struct mdns_interface *mi = NULL;
      SLIST_FOREACH(mi, &s_mdns_interfaces, next) {
        if (mi->local_ip4.sin_addr.s_addr == local_ip4) break;
      }
      if (mi == NULL) {
        LOG(LL_ERROR, ("Interface not inited! addr %#x", (int) local_ip4));
        return;
      }
      struct mgos_mdns_message mm = {
          .if_type = mi->if_type,
          .if_instance = mi->if_instance,
          .local_ip4 = mi->local_ip4,
          .dns_msg = (struct mg_dns_message *) ev_data,
      };
      SLIST_FOREACH(e, &s_mdns_handlers, next) {
        e->handler(nc, MGOS_EV_MDNS_MESSAGE, &mm, e->ud);
      }
      break;
    }
    case MG_EV_SEND: {
      if (nc != s_mdns_listener) break;
      struct mdns_interface *mi = NULL;
      SLIST_FOREACH(mi, &s_mdns_interfaces, next) {
        if (mi->pending.len > 0) break;
      }
      if (mi == NULL) break;
      struct mbuf *dst_buf = &nc->send_mbuf;
      mbuf_free(dst_buf);
      mbuf_move(&mi->pending, dst_buf);
      LOG(LL_DEBUG, ("%d.%d %s advertisement %x", mi->if_type, mi->if_instance,
                     "sent", (int) mi->local_ip4.sin_addr.s_addr));
      nc->priv_2 = (void *) (uintptr_t) mi->local_ip4.sin_addr.s_addr;
      break;
    }
    case MG_EV_CLOSE: {
      if (nc != s_mdns_listener) break;
      LOG(LL_ERROR, ("%p mDNS socket closed", s_mdns_listener));
      s_mdns_listener = NULL;
      break;
    }
  }
  (void) ev_data;
  (void) user_data;
}

static void mdns_join_group(void) {
  if (mgos_sys_config_get_dns_sd_adv_only()) return;
  LOG(LL_DEBUG, ("Joining %s", MDNS_MCAST_GROUP));
  if (!mgos_mdns_hal_join_group(MDNS_MCAST_GROUP)) {
    LOG(LL_ERROR, ("Failed to join %s", MDNS_MCAST_GROUP));
  }
}

void mgos_mdns_add_handler(mg_event_handler_t handler, void *ud) {
  struct mdns_handler *e = calloc(1, sizeof(*e));
  if (e == NULL) return;
  e->handler = handler;
  e->ud = ud;
  SLIST_INSERT_HEAD(&s_mdns_handlers, e, next);
}

void mgos_mdns_remove_handler(mg_event_handler_t handler, void *ud) {
  struct mdns_handler *e;
  SLIST_FOREACH(e, &s_mdns_handlers, next) {
    if (e->handler == handler && e->ud == ud) {
      SLIST_REMOVE(&s_mdns_handlers, e, mdns_handler, next);
      return;
    }
  }
}

struct mg_connection *get_listener(void) {
  if (s_mdns_listener != NULL) return s_mdns_listener;
  struct mg_connection *lc =
      mg_bind(mgos_get_mgr(), MDNS_LISTENER_SPEC, sock_ev_handler, NULL);
  LOG(LL_INFO, ("Listening on %s... %p", MDNS_LISTENER_SPEC, lc));
  if (lc == NULL) {
    LOG(LL_ERROR, ("Failed to listen"));
    return NULL;
  }
  mg_set_protocol_dns(lc);
  // Hack: replace address with mcast, for outgoing advertisements.
  inet_aton(MDNS_MCAST_GROUP, &lc->sa.sin.sin_addr);
  mdns_join_group();
  s_mdns_listener = lc;
  return lc;
}

static struct mdns_interface *get_interface(enum mgos_net_if_type if_type,
                                            int if_instance, bool create,
                                            bool recreate) {
  struct mdns_interface *mi = NULL;
  SLIST_FOREACH(mi, &s_mdns_interfaces, next) {
    if (mi->if_type == if_type && mi->if_instance == if_instance) {
      break;
    }
  }
  if (!create) return mi;
  if (mi != NULL) {
    if (!recreate) return mi;
    SLIST_REMOVE(&s_mdns_interfaces, mi, mdns_interface, next);
    free(mi);
    mi = NULL;
  }
  bool is_new = false;
  if (mi == NULL) {
    mi = calloc(1, sizeof(*mi));
    if (mi == NULL) {
      LOG(LL_ERROR, ("Out of memory"));
      return NULL;
    }
    mi->if_type = if_type;
    mi->if_instance = if_instance;
    is_new = true;
  }
  if (is_new) {
    SLIST_INSERT_HEAD(&s_mdns_interfaces, mi, next);
  }
  return mi;
}

static void notify_connected(struct mdns_interface *mi) {
  if (!mi->connected || mi->local_ip4.sin_addr.s_addr == 0) return;
  struct mgos_mdns_message mm = {
      .if_type = mi->if_type,
      .if_instance = mi->if_instance,
      .local_ip4 = mi->local_ip4,
      .dns_msg = NULL,
  };
  struct mdns_handler *e;
  SLIST_FOREACH(e, &s_mdns_handlers, next) {
    e->handler(s_mdns_listener, MG_EV_CONNECT, &mm, e->ud);
  }
}

static void mgos_mdns_net_ev_handler(int ev, void *evd, void *arg) {
  switch (ev) {
    case MGOS_NET_EV_CONNECTED:
      // fallthrough
    case MGOS_NET_EV_IP_ACQUIRED: {
      const struct mgos_net_event_data *ned = evd;
      bool recreate = (ev == MGOS_NET_EV_CONNECTED);
      struct mdns_interface *mi = get_interface(ned->if_type, ned->if_instance,
                                                true /* create */, recreate);
      if (mi != NULL) {
        if (ev == MGOS_NET_EV_CONNECTED) {
          mi->connected = true;
        } else {
          mi->local_ip4 = ned->ip_info.ip;
        }
        notify_connected(mi);
      }
      break;
    }
#ifdef MGOS_HAVE_WIFI
    case MGOS_WIFI_EV_AP_STA_CONNECTED: {
      struct mgos_net_ip_info ip_info;
      if (!mgos_net_get_ip_info(MGOS_NET_IF_TYPE_WIFI, MGOS_NET_IF_WIFI_AP,
                                &ip_info)) {
        break;
      }
      struct mdns_interface *mi =
          get_interface(MGOS_NET_IF_TYPE_WIFI, MGOS_NET_IF_WIFI_AP,
                        true /* create */, false /* recreate */);
      if (mi != NULL) {
        mi->connected = true;
        mi->local_ip4 = ip_info.ip;
        notify_connected(mi);
      }
      break;
    }
#endif
    case MGOS_NET_EV_DISCONNECTED: {
      const struct mgos_net_event_data *ned = evd;
      struct mdns_interface *mi =
          get_interface(ned->if_type, ned->if_instance, false /* create */,
                        false /* recreate */);
      if (mi != NULL) {
        SLIST_REMOVE(&s_mdns_interfaces, mi, mdns_interface, next);
        free(mi);
      }
      break;
    }
  }
  (void) ev;
  (void) evd;
  (void) arg;
}

bool mgos_mdns_advertise(enum mgos_net_if_type if_type, int if_instance,
                         struct mbuf *mb) {
  struct mdns_interface *mi = get_interface(
      if_type, if_instance, false /* create */, false /* recreate */);
  if (mi == NULL) {
    LOG(LL_DEBUG, ("%d.%d not found", if_type, if_instance));
    return false;
  }
  if (!mi->connected) {
    LOG(LL_ERROR, ("%d.%d is not connected", mi->if_type, mi->if_instance));
    return false;
  }
  if (mi->local_ip4.sin_addr.s_addr == 0) {
    LOG(LL_ERROR, ("%d.%d has no IP", mi->if_type, mi->if_instance));
    return false;
  }
  struct mg_connection *lc = get_listener();
  if (lc == NULL) {
    LOG(LL_ERROR, ("%d.%d no listener", mi->if_type, mi->if_instance));
    return false;
  }
  // Mongoose can only send one UDP message at a time.
  struct mbuf *dst_buf =
      (lc->send_mbuf.len == 0 ? &lc->send_mbuf : &mi->pending);
  mbuf_free(dst_buf);
  mbuf_move(mb, dst_buf);
  LOG(LL_DEBUG, ("%d.%d %s advertisement %x", mi->if_type, mi->if_instance,
                 (dst_buf == &lc->send_mbuf ? "sent" : "queued"),
                 (int) mi->local_ip4.sin_addr.s_addr));
  if (dst_buf == &lc->send_mbuf) {
    lc->priv_2 = (void *) (uintptr_t) mi->local_ip4.sin_addr.s_addr;
  }
  return true;
}

bool mgos_mdns_init(void) {
  mgos_event_add_group_handler(MGOS_EVENT_GRP_NET, mgos_mdns_net_ev_handler,
                               NULL);
#ifdef MGOS_HAVE_WIFI
  mgos_event_add_handler(MGOS_WIFI_EV_AP_STA_CONNECTED,
                         mgos_mdns_net_ev_handler, NULL);
#endif
  return true;
}
