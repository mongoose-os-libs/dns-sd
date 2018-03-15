/*
 * Copyright (c) 2014-2016 Cesanta Software Limited
 * All rights reserved
 */

#ifndef CS_MOS_LIBS_DNS_SD_SRC_MGOS_MDNS_INTERNAL_H_
#define CS_MOS_LIBS_DNS_SD_SRC_MGOS_MDNS_INTERNAL_H_

#include "mgos_mdns.h"

#include <stdbool.h>

#include "mgos_mongoose.h"

#ifdef __cplusplus
extern "C" {
#endif

bool mgos_mdns_init(void);

/* Join multicast group. */
void mgos_mdns_hal_join_group(const char *mcast_ip);

/* Leave multicast group. */
void mgos_mdns_hal_leave_group(const char *mcast_ip);

#ifdef __cplusplus
}
#endif

#endif /* CS_MOS_LIBS_DNS_SD_SRC_MGOS_MDNS_INTERNAL_H_ */
