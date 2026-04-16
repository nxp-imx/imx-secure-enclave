/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025-2026 NXP
 */

#ifndef SAB_PRIME_AUTH_H
#define SAB_PRIME_AUTH_H

/* PRIME commands */
#define PRIME_LOAD_HMAC_KEY_REQ		0x45
#define PRIME_LOAD_HMAC_KEY_REQ_SZ	0x8C

#define PRIME_HASH			0x80
#define PRIME_HMAC_GEN			0x88
#define PRIME_HMAC_VERIFY		0x89
#define PRIME_AUTH_SZ			0x18

/* PRIME message construction APIs, using mailbox to communicate with FW */
int prime_load_hmac_key(void *mu_base, const uint8_t *key, size_t keylen,
			uint8_t key_slot, uint8_t sha_algo);
void prime_auth_construct(uint32_t *mu_buf, uint8_t keyslot,
			  uint32_t src_addr, size_t len,
			  uint32_t digest_addr, uint8_t sha_algo,
			  uint8_t dir, uint8_t flag);

#endif /* SAB_PRIME_AUTH_H */
