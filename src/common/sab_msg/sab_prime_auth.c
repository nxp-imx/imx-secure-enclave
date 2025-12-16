/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025 NXP
 */

#include <stdio.h>
#include <string.h>

#include "sab_prime_api.h"
#include "sab_prime_auth.h"
#include "mu_regs.h"

void prime_auth_construct(uint32_t *mu_buf, uint8_t key_slot,
			  uint32_t src_addr, size_t len,
			  uint32_t digest_addr, uint8_t sha_algo,
			  uint8_t dir, uint8_t flag)
{
	struct prime_msg msg = {0};

	/* message header */
	msg.version = PRIME_VERSION;
	msg.size = PRIME_AUTH_SZ >> 2;
	msg.tag = PRIME_CMD_TAG;

	if (dir == 0)
		msg.command = PRIME_HMAC_GEN;
	else if (dir == 1)
		msg.command = PRIME_HMAC_VERIFY;
	else if (dir == 2)
		msg.command = PRIME_HASH;

	/* message data */
	msg.data[0] = 0x0;
	msg.data[1] = (key_slot << PRIME_KEY_SLOT_SHIFT) |
		      (sha_algo << 4) | flag;
	msg.data[2] = digest_addr;
	msg.data[3] = len;
	msg.data[4] = src_addr;

	imx_mu_word_copy(mu_buf, (uint32_t *)&msg, msg.size);
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
