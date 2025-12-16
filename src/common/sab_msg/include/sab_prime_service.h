/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025 NXP
 */

#ifndef SAB_PRIME_SERVICE_H
#define SAB_PRIME_SERVICE_H

/* PRIME commands */
#define PRIME_SERVICE_OPEN_REQ		0x10
#define PRIME_SERVICE_CLOSE_REQ		0x11
#define PRIME_SERVICE_REQ_SZ		0x4

int prime_service_open(void *mu_base);
void prime_service_close(void *mu_base);

#endif /* SAB_PRIME_SERVICE_H */
