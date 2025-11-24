/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025 NXP
 */

#include <stdio.h>
#include <string.h>

#include "sab_fce_api.h"
#include "sab_fce_aes.h"
#include "fce_mu_regs.h"

void fce_cbc_construct(uint32_t *mu_buf, uint8_t keyslot,
		       uint32_t src_addr, uint32_t dst_addr,
		       size_t len, uint8_t op,
		       uint8_t *iv, size_t ivlen,
		       uint32_t digest_addr, uint8_t sha_algo,
		       uint8_t flag)
{
	struct fce_msg msg = {0};

	/* message header */
	msg.version = FCE_VERSION;
	msg.size = FCE_CBC_SZ >> 2;
	msg.tag = FCE_CMD_TAG;

	if (op)
		msg.command = FCE_CBC_DEC;
	else
		msg.command = FCE_CBC_ENC;

	/* message data */
	msg.data[0] = 0x0;
	msg.data[1] = (keyslot << FCE_KEY_SLOT_SHIFT) |
		      (sha_algo << 4) | flag;
	msg.data[2] = digest_addr;
	msg.data[3] = len;
	msg.data[4] = src_addr;
	msg.data[5] = dst_addr;
	memcpy(&msg.data[6], iv, ivlen);

	imx_mu_word_copy(mu_buf, (uint32_t *)&msg, msg.size);
}

void fce_ecb_construct(uint32_t *mu_buf, uint8_t keyslot,
		       uint32_t src_addr, uint32_t dst_addr,
		       size_t len, uint8_t op,
		       uint32_t digest_addr, uint8_t sha_algo,
		       uint8_t flag)
{
	struct fce_msg msg = {0};

	/* message header */
	msg.version = FCE_VERSION;
	msg.size = FCE_ECB_SZ >> 2;
	msg.tag = FCE_CMD_TAG;

	if (op)
		msg.command = FCE_ECB_DEC;
	else
		msg.command = FCE_ECB_ENC;

	/* message data */
	msg.data[0] = 0x0;
	msg.data[1] = (keyslot << FCE_KEY_SLOT_SHIFT) |
		      (sha_algo << 4) | flag;
	msg.data[2] = digest_addr;
	msg.data[3] = len;
	msg.data[4] = src_addr;
	msg.data[5] = dst_addr;

	imx_mu_word_copy(mu_buf, (uint32_t *)&msg, msg.size);
}

void fce_gcm_construct(uint32_t *mu_buf, uint8_t keyslot,
		       uint32_t src_addr, uint32_t dst_addr,
		       size_t len, uint8_t op,
		       uint8_t *iv, size_t ivlen,
		       uint32_t aad_addr, size_t aadlen,
		       uint32_t tag_addr, size_t taglen,
		       uint8_t flag)
{
	struct fce_msg msg = {0};

	/* message header */
	msg.version = FCE_VERSION;
	msg.size = FCE_GCM_SZ >> 2;
	msg.tag = FCE_CMD_TAG;

	if (op)
		msg.command = FCE_GCM_DEC;
	else
		msg.command = FCE_GCM_ENC;

	/* message data */
	msg.data[0] = 0x0;
	msg.data[1] = (ivlen << 24) |
		      (keyslot << FCE_KEY_SLOT_SHIFT) |
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

int fce_load_aes_key(void *mu_base,
		     const uint8_t *key,
		     size_t keylen,
		     uint8_t keyslot)
{
	struct fce_load_key_msg msg = {0};
	int ret;

	/* message header */
	msg.version = FCE_VERSION;
	msg.size = FCE_LOAD_AES_KEY_REQ_SZ >> 2;
	msg.tag = FCE_CMD_TAG;
	msg.command = FCE_LOAD_AES_KEY_REQ;

	/* key info */
	msg.keyslot = keyslot;
	msg.keysize = keylen;

	/* key data */
	memcpy(&msg.data[0], key, keylen);

	/* crc */
	msg.data[8] = crc_compute((uint32_t *)&msg, FCE_LOAD_AES_KEY_REQ_SZ);

	ret = imx_mu_send_recv(mu_base, &msg, &msg);
	if (ret)
		printf("Load AES Key Error 0x%x", msg.data[0]);

	return ret;
}
