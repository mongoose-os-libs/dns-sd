/*
 * Copyright (c) 2014-2018 Cesanta Software Limited
 * All rights reserved
 */

#ifndef CS_MOS_LIBS_DNS_SD_INCLUDE_MGOS_DNS_SD_H_
#define CS_MOS_LIBS_DNS_SD_INCLUDE_MGOS_DNS_SD_H_

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Return currently configure DNS-SD hostname.
 */
const char *mgos_dns_sd_get_host_name(void);

#ifdef __cplusplus
}
#endif

#endif /* CS_MOS_LIBS_DNS_SD_INCLUDE_MGOS_DNS_SD_H_ */
