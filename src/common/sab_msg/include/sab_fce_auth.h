/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025 NXP
 */

#ifndef SAB_FCE_AUTH_H
#define SAB_FCE_AUTH_H

/* FCE commands */
#define FCE_LOAD_HMAC_KEY_REQ		0x45
#define FCE_LOAD_HMAC_KEY_REQ_SZ	0x8C

#define FCE_HASH			0x80
#define FCE_HMAC_GEN			0x88
#define FCE_HMAC_VERIFY			0x89
#define FCE_AUTH_SZ			0x18

/* FCE message construction APIs, using mailbox to communicate with FW */
int fce_load_hmac_key(void *mu_base, const uint8_t *key, size_t keylen,
		      uint8_t key_slot, uint8_t sha_algo);
void fce_auth_construct(uint32_t *mu_buf, uint8_t key_slot,
			uint32_t src_addr, size_t len,
			uint32_t digest_addr, uint8_t sha_algo,
			uint8_t dir, uint8_t flag);

#endif /* SAB_FCE_AUTH_H */
