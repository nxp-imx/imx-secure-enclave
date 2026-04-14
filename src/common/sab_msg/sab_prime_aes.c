/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025-2026 NXP
 */

#include <stdio.h>
#include <string.h>

#include "sab_prime_api.h"
#include "sab_prime_aes.h"
#include "mu_regs.h"

#define PRIME_SET_HDR(mu_reg, idx, msg_size, cmd) \
	(mu_reg[idx] = (PRIME_VERSION) | \
		       ((msg_size) >> 2) << 8 | \
		       (cmd) << 16 | \
		       (PRIME_CMD_TAG) << 24)

static void copy_bytes(volatile uint32_t *mu_reg, uint32_t offset,
		       const uint8_t *src, size_t srclen)
{
	volatile uint8_t *mu_reg_byte = (volatile uint8_t *)&mu_reg[offset];
	uint32_t j;

	for (j = 0; j < srclen; j++)
		mu_reg_byte[j] = src[j];
}

void prime_cbc_construct(uint32_t *mu_buf, uint8_t keyslot,
			 uint32_t src_addr, uint32_t dst_addr,
			 size_t len, uint8_t enc,
			 uint8_t *iv, size_t ivlen,
			 uint32_t digest_addr, uint8_t sha_algo,
			 uint8_t flag)
{
	struct prime_msg msg = {0};

	/* message header */
	msg.version = PRIME_VERSION;
	msg.size = PRIME_CBC_SZ >> 2;
	msg.tag = PRIME_CMD_TAG;

	if (enc)
		msg.command = PRIME_CBC_ENC;
	else
		msg.command = PRIME_CBC_DEC;

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

void prime_ctr_construct(uint32_t *mu_buf, uint8_t keyslot,
			 uint32_t src_addr, uint32_t dst_addr,
			 size_t len, uint8_t enc,
			 uint8_t *ctr, size_t ctrlen,
			 uint32_t digest_addr, uint8_t sha_algo,
			 uint8_t flag)
{
	uint8_t command;
	uint32_t i = 0, j;
	volatile uint32_t *mu_reg = (volatile uint32_t *)mu_buf;

	/* message header - packed into first word */
	if (enc)
		command = PRIME_CTR_ENC;
	else
		command = PRIME_CTR_DEC;

	/* message header - packed into first word */
	PRIME_SET_HDR(mu_reg, i++, PRIME_CTR_SZ, command);

	/* message data */
	mu_reg[i++] = 0x0;
	mu_reg[i++] = (keyslot << PRIME_KEY_SLOT_SHIFT) |
		      (sha_algo << 4) | flag;
	mu_reg[i++] = digest_addr;
	mu_reg[i++] = len;
	mu_reg[i++] = src_addr;
	mu_reg[i++] = dst_addr;

	/* Copy counter bytes */
	copy_bytes(mu_reg, i, ctr, ctrlen);
}

void prime_ecb_construct(uint32_t *mu_buf, uint8_t keyslot,
			 uint32_t src_addr, uint32_t dst_addr,
			 size_t len, uint8_t enc,
			 uint32_t digest_addr, uint8_t sha_algo,
			 uint8_t flag)
{
	struct prime_msg msg = {0};

	/* message header */
	msg.version = PRIME_VERSION;
	msg.size = PRIME_ECB_SZ >> 2;
	msg.tag = PRIME_CMD_TAG;

	if (enc)
		msg.command = PRIME_ECB_ENC;
	else
		msg.command = PRIME_ECB_DEC;

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
			 size_t len, uint8_t enc,
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

	if (enc)
		msg.command = PRIME_GCM_ENC;
	else
		msg.command = PRIME_GCM_DEC;

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
