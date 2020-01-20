/*
 * Copyright (c) 2020 Deomid "rojer" Ryabkov
 * All rights reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mgos_dns_sd.h"

#include <avahi-client/client.h>
#include <avahi-client/publish.h>
#include <avahi-common/alternative.h>
#include <avahi-common/error.h>
#include <avahi-common/malloc.h>
#include <avahi-common/simple-watch.h>
#include <avahi-common/strlst.h>

#include "common/queue.h"
#include "mgos.h"
#include "mgos_mongoose.h"

static AvahiClient *s_client = NULL;
static bool s_is_running = false;

struct mgos_dns_sd_service_entry {
  char *name;
  char *proto;
  int port;
  char *actual_name;  // After conflict resolution.
  AvahiStringList *txt;
  AvahiEntryGroup *group;
  SLIST_ENTRY(mgos_dns_sd_service_entry) next;
};

SLIST_HEAD(s_names, mgos_dns_sd_service_entry) s_names;

static const char *get_actual_name(const struct mgos_dns_sd_service_entry *e) {
  return (e->actual_name ? e->actual_name : e->name);
}

static void create_services(struct mgos_dns_sd_service_entry *e) {
  if (!s_is_running) return;
  if (!avahi_entry_group_is_empty(e->group)) return;
  const char *name = get_actual_name(e);
  int ret = avahi_entry_group_add_service_strlst(
      e->group, AVAHI_IF_UNSPEC, AVAHI_PROTO_INET, 0 /* flags */, name,
      e->proto, NULL /* domain */, NULL /* hostname */, e->port, e->txt);
  if (ret == 0) {
    ret = avahi_entry_group_commit(e->group);
  }
  LOG(LL_DEBUG, ("Added service %s.%s, ret %d", name, e->proto, ret));
}

static void avahi_entry_group_callback(AvahiEntryGroup *g,
                                       AvahiEntryGroupState state,
                                       void *userdata) {
  struct mgos_dns_sd_service_entry *e = userdata;
  switch (state) {
    case AVAHI_ENTRY_GROUP_ESTABLISHED: {
      LOG(LL_DEBUG, ("%s.%s: established", get_actual_name(e), e->proto));
      break;
    }
    case AVAHI_ENTRY_GROUP_COLLISION: {
      char *n;
      n = avahi_alternative_service_name(get_actual_name(e));
      avahi_free(e->actual_name);
      e->actual_name = n;
      LOG(LL_INFO,
          ("%s.%s: Name collision, renaming to %s", e->name, e->proto, n));
      create_services(e);
      break;
    }
    case AVAHI_ENTRY_GROUP_FAILURE:
      LOG(LL_ERROR,
          ("Entry group failure: %s", avahi_strerror(avahi_client_errno(
                                          avahi_entry_group_get_client(g)))));
      abort();
      break;
    case AVAHI_ENTRY_GROUP_UNCOMMITED:
      LOG(LL_DEBUG, ("%s.%s: uncommitted", get_actual_name(e), e->proto));
      break;
    case AVAHI_ENTRY_GROUP_REGISTERING:
      LOG(LL_DEBUG, ("%s.%s: registering", get_actual_name(e), e->proto));
      break;
  }
}

static void avahi_client_callback(AvahiClient *c, AvahiClientState state,
                                  void *userdata) {
  struct mgos_dns_sd_service_entry *e;
  switch (state) {
    case AVAHI_CLIENT_S_RUNNING:
      s_is_running = true;
      LOG(LL_INFO, ("Avahi client is running"));
      /* The server has startup successfully and registered its host
       * name on the network, so it's time to create our services */
      SLIST_FOREACH(e, &s_names, next) {
        create_services(e);
      };
      break;
    case AVAHI_CLIENT_FAILURE:
      LOG(LL_INFO,
          ("Avahi client error: %s", avahi_strerror(avahi_client_errno(c))));
      abort();
      break;
    case AVAHI_CLIENT_S_COLLISION:
      /* Let's drop our registered services. When the server is back
       * in AVAHI_SERVER_RUNNING state we will register them
       * again with the new host name. */
      // fall through
    case AVAHI_CLIENT_S_REGISTERING: {
      /* The server records are now being established. This
       * might be caused by a host name change. We need to wait
       * for our own records to register until the host name is
       * properly esatblished. */
      struct mgos_dns_sd_service_entry *e;
      SLIST_FOREACH(e, &s_names, next) {
        avahi_entry_group_reset(e->group);
      };
      s_is_running = false;
      break;
    }
    case AVAHI_CLIENT_CONNECTING:
      break;
  }
  (void) userdata;
}

static void mgos_dns_sd_service_entry_free(
    struct mgos_dns_sd_service_entry *e) {
  if (e == NULL) return;
  free(e->name);
  free(e->proto);
  free(e->actual_name);
  avahi_entry_group_reset(e->group);
  avahi_entry_group_free(e->group);
  avahi_string_list_free(e->txt);
  free(e);
}

bool mgos_dns_sd_add_service_instance(
    const char *name, const char *proto, int port,
    const struct mgos_dns_sd_txt_entry *txt_entries) {
  bool res = false, is_new = false;
  struct mgos_dns_sd_service_entry *e = NULL;
  const struct mgos_dns_sd_txt_entry *te;
  if (s_client == NULL) return false;
  SLIST_FOREACH(e, &s_names, next) {
    if (e->port == port && strcasecmp(e->name, name) == 0 &&
        strcasecmp(e->proto, proto) == 0) {
      break;
    }
  };
  if (e == NULL) {
    e = (struct mgos_dns_sd_service_entry *) calloc(1, sizeof(*e));
    if (e == NULL) goto out;
    e->name = strdup(name);
    e->proto = strdup(proto);
    e->port = port;
    e->group = avahi_entry_group_new(s_client, avahi_entry_group_callback, e);
    is_new = true;
  }
  avahi_string_list_free(e->txt);
  e->txt = avahi_string_list_new(NULL, NULL);
  for (te = txt_entries; te != NULL && te->key != NULL; te++) {
    char buf[200] = {0};
    snprintf(buf, sizeof(buf), "%s=%.*s", te->key, (int) te->value.len,
             te->value.p);
    e->txt = avahi_string_list_add(e->txt, buf);
  }
  res = true;

out:
  if (is_new) {
    if (res) {
      SLIST_INSERT_HEAD(&s_names, e, next);
    } else {
      mgos_dns_sd_service_entry_free(e);
    }
  }
  if (res) {
    avahi_entry_group_reset(e->group);
    create_services(e);
  }
  return res;
}

bool mgos_dns_sd_remove_service_instance(const char *name, const char *proto,
                                         int port) {
  // TODO.
  (void) name;
  (void) proto;
  (void) port;
  return false;
}

const char *mgos_dns_sd_get_host_name(void) {
  return avahi_client_get_host_name_fqdn(s_client);
}

void mgos_dns_sd_advertise(void) {
  // no-op
}

void mgos_dns_sd_goodbye(void) {
  // TODO
}

static void avahi_poll_cb(void *arg) {
  avahi_simple_poll_iterate((AvahiSimplePoll *) arg, 0);
}

bool mgos_dns_sd_init(void) {
  if (!mgos_sys_config_get_dns_sd_enable()) return true;

  AvahiSimplePoll *sp = avahi_simple_poll_new();
  if (sp == NULL) return false;

  int error;
  s_client = avahi_client_new(avahi_simple_poll_get(sp), 0,
                              avahi_client_callback, NULL, &error);
  if (s_client == NULL) {
    LOG(LL_ERROR, ("Failed to create Avahi client: %s", avahi_strerror(error)));
    return false;
  }

  LOG(LL_INFO, ("Avahi client created"));

  mgos_add_poll_cb(avahi_poll_cb, sp);

  return true;
}
