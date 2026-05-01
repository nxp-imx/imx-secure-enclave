/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2026 NXP
 */

#ifndef SAB_PRIME_INFO_H
#define SAB_PRIME_INFO_H

#include "internal/prime_info.h"

/* PRIME commands */
#define PRIME_GET_INFO_REQ		0x18
#define PRIME_GET_INFO_REQ_SZ		0x4

#define FW_MAJOR_SHIFT        16
#define FW_MINOR_SHIFT        8
#define FW_VERSION_MASK       0xFF

/* PRIME message construction APIs, using mailbox to communicate with FW */
int process_prime_get_info(void *mu_base, prime_info_t *args);

#endif /* SAB_PRIME_INFO_H */
