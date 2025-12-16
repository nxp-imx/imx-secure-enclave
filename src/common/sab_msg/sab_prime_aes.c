/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025 NXP
 */

#include <stdio.h>
#include <string.h>

#include "sab_prime_api.h"
#include "sab_prime_aes.h"
#include "mu_regs.h"

void prime_cbc_construct(uint32_t *mu_buf, uint8_t keyslot,
			 uint32_t src_addr, uint32_t dst_addr,
			 size_t len, uint8_t op,
			 uint8_t *iv, size_t ivlen,
			 uint32_t digest_addr, uint8_t sha_algo,
			 uint8_t flag)
{
	struct prime_msg msg = {0};

	/* message header */
	msg.version = PRIME_VERSION;
	msg.size = PRIME_CBC_SZ >> 2;
	msg.tag = PRIME_CMD_TAG;

	if (op)
		msg.command = PRIME_CBC_DEC;
	else
		msg.command = PRIME_CBC_ENC;

	/* message data */
	msg.data[0] = 0x0;
	msg.data[1] = (keyslot << PRIME_KEY_SLOT_SHIFT) |
		      (sha_algo << 4) | flag;
	msg.data[2] = digest_addr;
	msg.data[3] = len;
	msg.data[4] = src_addr;
	msg.data[5] = dst_addr;
	memcpy(&msg.data[6], iv, ivlen);

	imx_mu_word_copy(mu_buf, (uint32_t *)&msg, msg.size);
}

void prime_ecb_construct(uint32_t *mu_buf, uint8_t keyslot,
			 uint32_t src_addr, uint32_t dst_addr,
			 size_t len, uint8_t op,
			 uint32_t digest_addr, uint8_t sha_algo,
			 uint8_t flag)
{
	struct prime_msg msg = {0};

	/* message header */
	msg.version = PRIME_VERSION;
	msg.size = PRIME_ECB_SZ >> 2;
	msg.tag = PRIME_CMD_TAG;

	if (op)
		msg.command = PRIME_ECB_DEC;
	else
		msg.command = PRIME_ECB_ENC;

	/* message data */
	msg.data[0] = 0x0;
	msg.data[1] = (keyslot << PRIME_KEY_SLOT_SHIFT) |
		      (sha_algo << 4) | flag;
	msg.data[2] = digest_addr;
	msg.data[3] = len;
	msg.data[4] = src_addr;
	msg.data[5] = dst_addr;

	imx_mu_word_copy(mu_buf, (uint32_t *)&msg, msg.size);
}

void prime_gcm_construct(uint32_t *mu_buf, uint8_t keyslot,
			 uint32_t src_addr, uint32_t dst_addr,
			 size_t len, uint8_t op,
			 uint8_t *iv, size_t ivlen,
			 uint32_t aad_addr, size_t aadlen,
			 uint32_t tag_addr, size_t taglen,
			 uint8_t flag)
{
	struct prime_msg msg = {0};

	/* message header */
	msg.version = PRIME_VERSION;
	msg.size = PRIME_GCM_SZ >> 2;
	msg.tag = PRIME_CMD_TAG;

	if (op)
		msg.command = PRIME_GCM_DEC;
	else
		msg.command = PRIME_GCM_ENC;

	/* message data */
	msg.data[0] = 0x0;
	msg.data[1] = (ivlen << 24) |
		      (keyslot << PRIME_KEY_SLOT_SHIFT) |
		      (taglen << 8) | flag;
	msg.data[2] = tag_addr;
	msg.data[3] = len;
	msg.data[4] = src_addr;
	msg.data[5] = dst_addr;
	memcpy(&msg.data[6], iv, ivlen);
	msg.data[10] = aadlen;
	msg.data[11] = aad_addr;

	imx_mu_word_copy(mu_buf, (uint32_t *)&msg, msg.size);
}

int prime_load_aes_key(void *mu_base,
		       const uint8_t *key,
		       size_t keylen,
		       uint8_t keyslot)
{
	struct prime_load_key_msg msg = {0};
	int ret;

	/* message header */
	msg.version = PRIME_VERSION;
	msg.size = PRIME_LOAD_AES_KEY_REQ_SZ >> 2;
	msg.tag = PRIME_CMD_TAG;
	msg.command = PRIME_LOAD_AES_KEY_REQ;

	/* key info */
	msg.keyslot = keyslot;
	msg.keysize = keylen;

	/* key data */
	memcpy(&msg.data[0], key, keylen);

	/* crc */
	msg.data[8] = crc_compute((uint32_t *)&msg, PRIME_LOAD_AES_KEY_REQ_SZ);

	ret = imx_mu_send_recv(mu_base, &msg, &msg);
	if (ret)
		printf("Load AES Key Error 0x%x", msg.data[0]);

	return ret;
}
