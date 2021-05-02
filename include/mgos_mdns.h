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
 * Multicast DNS API.
 *
 * See https://en.wikipedia.org/wiki/Multicast_DNS for for information
 * about the multicast DNS.
 */

#pragma once

#include "mgos_net.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MGOS_EV_MDNS_MESSAGE 111
struct mgos_mdns_message {
  enum mgos_net_if_type if_type;
  int if_instance;
  struct sockaddr_in local_ip4;
  struct mg_dns_message *dns_msg;
};

/*
 * Register a mDNS event handler `handler` with the arbitrary userdata `ud`.
 *
 * Example:
 *
 * ```c
 * static void handler(struct mg_connection *nc, int ev, void *ev_data,
 *                     void *user_data) {
 *   if (ev == MG_DNS_MESSAGE) {
 *     struct mg_dns_message *msg = (struct mg_dns_message *) ev_data;
 *     char *peer = inet_ntoa(nc->sa.sin.sin_addr);
 *     LOG(LL_DEBUG, ("---- DNS packet from %s (%d questions, %d answers)",
 *                    peer, msg->num_questions, msg->num_answers));
 *   }
 *
 *   (void) user_data;
 * }
 *
 * ....
 *
 * // Somewhere else:
 * mgos_mdns_add_handler(handler, NULL)
 * ```
 */
void mgos_mdns_add_handler(mg_event_handler_t handler, void *ud);

/*
 * Unregister a previously registered event handler with the given userdata
 * `ud`.
 */
void mgos_mdns_remove_handler(mg_event_handler_t handler, void *ud);

/*
 * Send an advertisement message on the specified interface.
 * Takes over mbuf and frees mbuf if successful.
 */
struct mg_dns_reply;
bool mgos_mdns_advertise(enum mgos_net_if_type if_type, int if_instance,
                         struct mbuf *mb);

#ifdef __cplusplus
}
#endif
