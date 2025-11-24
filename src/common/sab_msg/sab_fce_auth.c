/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025 NXP
 */

#include <stdio.h>
#include <string.h>

#include "sab_fce_api.h"
#include "sab_fce_auth.h"
#include "fce_mu_regs.h"

void fce_auth_construct(uint32_t *mu_buf, uint8_t key_slot,
			uint32_t src_addr, size_t len,
			uint32_t digest_addr, uint8_t sha_algo,
			uint8_t dir, uint8_t flag)
{
	struct fce_msg msg = {0};

	/* message header */
	msg.version = FCE_VERSION;
	msg.size = FCE_AUTH_SZ >> 2;
	msg.tag = FCE_CMD_TAG;

	if (dir == 0)
		msg.command = FCE_HMAC_GEN;
	else if (dir == 1)
		msg.command = FCE_HMAC_VERIFY;
	else if (dir == 2)
		msg.command = FCE_HASH;

	/* message data */
	msg.data[0] = 0x0;
	msg.data[1] = (key_slot << FCE_KEY_SLOT_SHIFT) |
		      (sha_algo << 4) | flag;
	msg.data[2] = digest_addr;
	msg.data[3] = len;
	msg.data[4] = src_addr;

	imx_mu_word_copy(mu_buf, (uint32_t *)&msg, msg.size);
}

int fce_load_hmac_key(void *mu_base,
		      const uint8_t *key,
		      size_t keylen,
		      uint8_t key_slot,
		      uint8_t sha_algo)
{
	struct fce_msg msg = {0};
	int ret;

	/* message header */
	msg.version = FCE_VERSION;
	msg.size = FCE_LOAD_HMAC_KEY_REQ_SZ >> 2;
	msg.tag = FCE_CMD_TAG;
	msg.command = FCE_LOAD_HMAC_KEY_REQ;

	/* message data */
	msg.data[0] = (sha_algo << 8) | key_slot;
	memcpy(&msg.data[1], key, keylen);
	msg.data[33] = crc_compute((uint32_t *)&msg, FCE_LOAD_HMAC_KEY_REQ_SZ);

	ret = imx_mu_send_recv(mu_base, &msg, &msg);
	if (ret)
		printf("Load HMAC Key Err 0x%x", msg.data[0]);

	return ret;
}
