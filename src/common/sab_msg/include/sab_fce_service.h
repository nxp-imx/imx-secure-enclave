/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025 NXP
 */

#ifndef SAB_FCE_SERVICE_H
#define SAB_FCE_SERVICE_H

/* FCE commands */
#define FCE_SERVICE_OPEN_REQ		0x10
#define FCE_SERVICE_CLOSE_REQ		0x11
#define FCE_SERVICE_REQ_SZ		0x4

int fce_service_open(void *mu_base);
void fce_service_close(void *mu_base);

#endif /* SAB_FCE_SERVICE_H */
