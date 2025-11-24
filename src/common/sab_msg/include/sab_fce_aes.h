/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025 NXP
 */

#ifndef SAB_FCE_AES_H
#define SAB_FCE_AES_H

/* FCE commands */
#define FCE_LOAD_AES_KEY_REQ		0x41
#define FCE_LOAD_AES_KEY_REQ_SZ		0x2C

#define FCE_ECB_ENC			0x60
#define FCE_ECB_DEC			0x61
#define FCE_ECB_SZ			0x1C

#define FCE_CBC_ENC			0x64
#define FCE_CBC_DEC			0x65
#define FCE_CBC_SZ			0x2C

#define FCE_GCM_ENC			0x68
#define FCE_GCM_DEC			0x69
#define FCE_GCM_SZ			0x34

/* FCE message construction APIs, using mailbox to communicate with FW */
int fce_load_aes_key(void *mu_base, const uint8_t *key, size_t keylen,
		     uint8_t key_slot);
void fce_cbc_construct(uint32_t *mu_buf, uint8_t keyslot,
		       uint32_t src_addr, uint32_t dst_addr,
		       size_t len, uint8_t op,
		       uint8_t *iv, size_t ivlen,
		       uint32_t digest_addr, uint8_t sha_algo,
		       uint8_t flag);
void fce_ecb_construct(uint32_t *mu_buf, uint8_t keyslot,
		       uint32_t src_addr, uint32_t dst_addr,
		       size_t len, uint8_t op,
		       uint32_t digest_addr, uint8_t sha_algo,
		       uint8_t flag);
void fce_gcm_construct(uint32_t *mu_buf, uint8_t keyslot,
		       uint32_t src_addr, uint32_t dst_addr,
		       size_t len, uint8_t op,
		       uint8_t *iv, size_t ivlen,
		       uint32_t aad_addr, size_t aadlen,
		       uint32_t tag_addr, size_t taglen,
		       uint8_t flag);

#endif /* SAB_FCE_AES_H */
