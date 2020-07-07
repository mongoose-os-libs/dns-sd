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
  SLIST_ENTRY(mdns_handler) entries;
  mg_event_handler_t handler;
  void *ud;
};

static struct mg_connection *s_listening_mdns_conn;

SLIST_HEAD(mdns_handlers, mdns_handler) s_mdns_handlers;

static void sock_ev_handler(struct mg_connection *nc, int ev, void *ev_data,
                            void *user_data) {
  struct mdns_handler *e;
  SLIST_FOREACH(e, &s_mdns_handlers, entries) {
    e->handler(nc, ev, ev_data, e->ud);
  }
  /* On close, invalidate listener - reconnect */
  if (ev == MG_EV_CLOSE && nc == s_listening_mdns_conn) {
    LOG(LL_ERROR, ("mDNS socket closed"));
    s_listening_mdns_conn = NULL;
    // Re-create.
    mgos_mdns_get_listener();
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

struct mg_connection *mgos_mdns_get_listener(void) {
  if (s_listening_mdns_conn != NULL) return s_listening_mdns_conn;

  struct mg_connection *lc =
      mg_bind(mgos_get_mgr(), MDNS_LISTENER_SPEC, sock_ev_handler, NULL);
  if (lc == NULL) {
    LOG(LL_ERROR, ("Failed to listen on %s", MDNS_LISTENER_SPEC));
    return NULL;
  }
  mg_set_protocol_dns(lc);
  LOG(LL_INFO, ("Listening on %s", MDNS_LISTENER_SPEC));

  /*
   * we had to bind on 0.0.0.0, but now we can store our mdns dest here
   * so we don't need to create a new connection in order to send outbound
   * mcast traffic.
   */
  lc->sa.sin.sin_port = htons(5353);
  inet_aton(MDNS_MCAST_GROUP, &lc->sa.sin.sin_addr);

  mdns_join_group();

  s_listening_mdns_conn = lc;

  return lc;
}

void mgos_mdns_add_handler(mg_event_handler_t handler, void *ud) {
  struct mdns_handler *e = calloc(1, sizeof(*e));
  if (e == NULL) return;
  e->handler = handler;
  e->ud = ud;
  SLIST_INSERT_HEAD(&s_mdns_handlers, e, entries);
}

void mgos_mdns_remove_handler(mg_event_handler_t handler, void *ud) {
  struct mdns_handler *e;
  SLIST_FOREACH(e, &s_mdns_handlers, entries) {
    if (e->handler == handler && e->ud == ud) {
      SLIST_REMOVE(&s_mdns_handlers, e, mdns_handler, entries);
      return;
    }
  }
}

static void mdns_net_ev_handler(int ev, void *evd, void *arg) {
  mdns_join_group();
  (void) ev;
  (void) evd;
  (void) arg;
}

bool mgos_mdns_init(void) {
  mgos_event_add_handler(MGOS_NET_EV_IP_ACQUIRED, mdns_net_ev_handler, NULL);
#ifdef MGOS_HAVE_WIFI
  mgos_event_add_handler(MGOS_WIFI_EV_AP_STA_CONNECTED, mdns_net_ev_handler,
                         NULL);
#endif
  return true;
}
