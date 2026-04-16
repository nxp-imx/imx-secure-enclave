/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025-2026 NXP
 */

#include <stdio.h>
#include <string.h>

#include "sab_prime_api.h"
#include "sab_prime_auth.h"
#include "mu_regs.h"

void prime_auth_construct(uint32_t *mu_buf, uint8_t keyslot,
			  uint32_t src_addr, size_t len,
			  uint32_t digest_addr, uint8_t sha_algo,
			  uint8_t dir, uint8_t flag)
{
	volatile uint32_t *mu_reg = (volatile uint32_t *)mu_buf;
	uint8_t command;
	uint32_t i = 0;

	if (dir == 0)
		command = PRIME_HMAC_GEN;
	else if (dir == 1)
		command = PRIME_HMAC_VERIFY;
	else if (dir == 2)
		command = PRIME_HASH;

	/* message header - packed into first word */
	PRIME_SET_HDR(mu_reg, i++, PRIME_AUTH_SZ, command);

	/* message data */
	mu_reg[i++] = 0x0;
	mu_reg[i++] = (keyslot << PRIME_KEY_SLOT_SHIFT) |
		      (sha_algo << 4) | flag;
	mu_reg[i++] = digest_addr;
	mu_reg[i++] = len;
	mu_reg[i] = src_addr;
}

int prime_load_hmac_key(void *mu_base,
			const uint8_t *key,
			size_t keylen,
			uint8_t key_slot,
			uint8_t sha_algo)
{
	struct prime_msg msg = {0};
	int ret;

	/* message header */
	msg.version = PRIME_VERSION;
	msg.size = PRIME_LOAD_HMAC_KEY_REQ_SZ >> 2;
	msg.tag = PRIME_CMD_TAG;
	msg.command = PRIME_LOAD_HMAC_KEY_REQ;

	/* message data */
	msg.data[0] = (sha_algo << 8) | key_slot;
	memcpy(&msg.data[1], key, keylen);
	msg.data[33] = crc_compute((uint32_t *)&msg, PRIME_LOAD_HMAC_KEY_REQ_SZ);

	ret = imx_mu_send_recv(mu_base, &msg, &msg);
	if (ret)
		printf("Load HMAC Key Err 0x%x", msg.data[0]);

	return ret;
}
