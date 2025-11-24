/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025 NXP
 */

#ifndef SAB_FCE_API_H
#define SAB_FCE_API_H

#include <stdint.h>

/* FCE commands */
#define FCE_VERSION			0x02
#define FCE_CMD_TAG			0x1B

#define FCE_KEY_SLOT_SHIFT		0x10

#define FCE_PUSH_REQ(SLOT)		(0xB0 | (SLOT))
#define FCE_PUSH_REQ_SZ			0x4

#define FCE_GET_REQ_STATUS		0xC0
#define FCE_GET_REQ_STATUS_SZ		0x8
#define FCE_REQ_ONGOING			0x10D6

/* FCE APIs, using mailbox to communicate with FW */
uint32_t crc_compute(uint32_t *msg, size_t len);
void imx_mu_word_copy(uint32_t *buf, uint32_t *data, uint8_t size);
int fce_push(void *mu_base, uint8_t slot);
int fce_get_request_status(void *mu_base, uint32_t *req_id);
int fce_read_clear_gsr(void *mu_base);

#endif /* SAB_FCE_API_H */
