/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025 NXP
 */

#ifndef SAB_PRIME_AES_H
#define SAB_PRIME_AES_H

/* PRIME commands */
#define PRIME_LOAD_AES_KEY_REQ		0x41
#define PRIME_LOAD_AES_KEY_REQ_SZ	0x2C

#define PRIME_ECB_ENC			0x60
#define PRIME_ECB_DEC			0x61
#define PRIME_ECB_SZ			0x1C

#define PRIME_CBC_ENC			0x64
#define PRIME_CBC_DEC			0x65
#define PRIME_CBC_SZ			0x2C

#define PRIME_GCM_ENC			0x68
#define PRIME_GCM_DEC			0x69
#define PRIME_GCM_SZ			0x34

/* PRIME message construction APIs, using mailbox to communicate with FW */
int prime_load_aes_key(void *mu_base, const uint8_t *key, size_t keylen,
		       uint8_t key_slot);
void prime_cbc_construct(uint32_t *mu_buf, uint8_t keyslot,
			 uint32_t src_addr, uint32_t dst_addr,
			 size_t len, uint8_t op,
			 uint8_t *iv, size_t ivlen,
			 uint32_t digest_addr, uint8_t sha_algo,
			 uint8_t flag);
void prime_ecb_construct(uint32_t *mu_buf, uint8_t keyslot,
			 uint32_t src_addr, uint32_t dst_addr,
			 size_t len, uint8_t op,
			 uint32_t digest_addr, uint8_t sha_algo,
			 uint8_t flag);
void prime_gcm_construct(uint32_t *mu_buf, uint8_t keyslot,
			 uint32_t src_addr, uint32_t dst_addr,
			 size_t len, uint8_t op,
			 uint8_t *iv, size_t ivlen,
			 uint32_t aad_addr, size_t aadlen,
			 uint32_t tag_addr, size_t taglen,
			 uint8_t flag);

#endif /* SAB_PRIME_AES_H */
