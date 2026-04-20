/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025-2026 NXP
 */

#include <stdio.h>
#include <string.h>

#include "sab_prime_api.h"
#include "sab_prime_aes.h"
#include "mu_regs.h"

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
			 uint8_t flag, uint32_t status_addr)
{
	volatile uint32_t *mu_reg = (volatile uint32_t *)mu_buf;
	uint8_t command;
	uint32_t i = 0;

	if (enc)
		command = PRIME_CBC_ENC;
	else
		command = PRIME_CBC_DEC;

	/* message header - packed into first word */
	PRIME_SET_HDR(mu_reg, i++, PRIME_CBC_SZ, command);

	/* message data */
	mu_reg[i++] = status_addr;
	mu_reg[i++] = (keyslot << PRIME_KEY_SLOT_SHIFT) |
		      (sha_algo << 4) | flag;
	mu_reg[i++] = digest_addr;
	mu_reg[i++] = len;
	mu_reg[i++] = src_addr;
	mu_reg[i++] = dst_addr;

	/* Copy iv bytes */
	copy_bytes(mu_reg, i, iv, ivlen);
}

void prime_ctr_construct(uint32_t *mu_buf, uint8_t keyslot,
			 uint32_t src_addr, uint32_t dst_addr,
			 size_t len, uint8_t enc,
			 uint8_t *ctr, size_t ctrlen,
			 uint32_t digest_addr, uint8_t sha_algo,
			 uint8_t flag, uint32_t status_addr)
{
	volatile uint32_t *mu_reg = (volatile uint32_t *)mu_buf;
	uint8_t command;
	uint32_t i = 0;

	if (enc)
		command = PRIME_CTR_ENC;
	else
		command = PRIME_CTR_DEC;

	/* message header - packed into first word */
	PRIME_SET_HDR(mu_reg, i++, PRIME_CTR_SZ, command);

	/* message data */
	mu_reg[i++] = status_addr;
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
			 uint8_t flag, uint32_t status_addr)
{
	volatile uint32_t *mu_reg = (volatile uint32_t *)mu_buf;
	uint8_t command;
	uint32_t i = 0;

	if (enc)
		command = PRIME_ECB_ENC;
	else
		command = PRIME_ECB_DEC;

	/* message header - packed into first word */
	PRIME_SET_HDR(mu_reg, i++, PRIME_ECB_SZ, command);

	/* message data */
	mu_reg[i++] = status_addr;
	mu_reg[i++] = (keyslot << PRIME_KEY_SLOT_SHIFT) |
		      (sha_algo << 4) | flag;
	mu_reg[i++] = digest_addr;
	mu_reg[i++] = len;
	mu_reg[i++] = src_addr;
	mu_reg[i] = dst_addr;
}

void prime_gcm_construct(uint32_t *mu_buf, uint8_t keyslot,
			 uint32_t src_addr, uint32_t dst_addr,
			 size_t len, uint8_t enc,
			 uint8_t *iv, size_t ivlen,
			 uint32_t aad_addr, size_t aadlen,
			 uint32_t tag_addr, size_t taglen,
			 uint8_t flag, uint32_t status_addr)
{
	volatile uint32_t *mu_reg = (volatile uint32_t *)mu_buf;
	uint8_t command;
	uint32_t i = 0;

	if (enc)
		command = PRIME_GCM_ENC;
	else
		command = PRIME_GCM_DEC;

	/* message header - packed into first word */
	PRIME_SET_HDR(mu_reg, i++, PRIME_GCM_SZ, command);

	/* message data */
	mu_reg[i++] = status_addr;
	mu_reg[i++] = (ivlen << 24) |
		      (keyslot << PRIME_KEY_SLOT_SHIFT) |
		      (taglen << 8) | flag;
	mu_reg[i++] = tag_addr;
	mu_reg[i++] = len;
	mu_reg[i++] = src_addr;
	mu_reg[i++] = dst_addr;

	/* Copy iv bytes */
	copy_bytes(mu_reg, i, iv, ivlen);

	mu_reg[11] = aadlen;
	mu_reg[12] = aad_addr;
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
