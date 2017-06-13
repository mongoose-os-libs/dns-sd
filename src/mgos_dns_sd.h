/*
 * Copyright (c) 2014-2016 Cesanta Software Limited
 * All rights reserved
 */

#ifndef CS_FW_SRC_MGOS_DNS_SD_H_
#define CS_FW_SRC_MGOS_DNS_SD_H_

#include <stdbool.h>

#include "common/mbuf.h"
#include "common/mg_str.h"
#include "common/platform.h"
#include "common/queue.h"
#include "fw/src/mgos_features.h"
#include "fw/src/mgos_init.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

bool mgos_dns_sd_init(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* CS_FW_SRC_MGOS_DNS_SD_H_ */
