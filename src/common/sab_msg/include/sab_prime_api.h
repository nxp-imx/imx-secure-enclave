/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025-2026 NXP
 */

#ifndef SAB_PRIME_API_H
#define SAB_PRIME_API_H

#include <stdint.h>

/* PRIME commands */
#define PRIME_VERSION			0x02
#define PRIME_CMD_TAG			0x1B

#define PRIME_MSG_HDR_INIT(msg, cmd, sz) \
	do { \
		typeof(msg) _msg = (msg); \
		_msg->version = PRIME_VERSION; \
		_msg->size = (sz) >> 2; \
		_msg->tag = PRIME_CMD_TAG; \
		_msg->command = (cmd); \
	} while (0)

#define PRIME_KEY_SLOT_SHIFT		0x10

#define PRIME_PUSH_REQ(SLOT)		(0xB0 | (SLOT))
#define PRIME_PUSH_REQ_SZ		0x4

#define PRIME_GET_REQ_STATUS		0xC0
#define PRIME_GET_REQ_STATUS_SZ		0x8
#define PRIME_REQ_ONGOING		0x10D6

#define TIMEOUT		10000

/* PRIME APIs, using mailbox to communicate with FW */
uint32_t crc_compute(uint32_t *msg, size_t len);
int prime_push(void *mu_base, uint8_t slot);
int prime_deq(int uio_fd);

#endif /* SAB_PRIME_API_H */
