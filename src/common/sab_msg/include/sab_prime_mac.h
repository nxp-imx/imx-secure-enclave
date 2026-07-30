/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025-2026 NXP
 */

#ifndef SAB_PRIME_MAC_H
#define SAB_PRIME_MAC_H

/* PRIME FCE (Fast Crypto Engine) command IDs */
#define PRIME_LOAD_HMAC_KEY_REQ		0x45
#define PRIME_LOAD_HMAC_KEY_REQ_SZ	0x8C

#define PRIME_HASH			0x80	/* FCE HASH Generate */
#define PRIME_HMAC_GEN			0x88	/* FCE HMAC Generate */
#define PRIME_HMAC_VERIFY		0x89	/* FCE HMAC Verify   */

/*
 * FCE message size (bytes, no CRC in MU slot buffer)
 * HASH Generate: 6 words = 0x18 bytes
 *   W0: Header
 *   W1: Status Address
 *   W2: Reserved | Flags
 *   W3: Digest Address
 *   W4: Payload Byte Length
 *   W5: Input Address
 */
#define PRIME_AUTH_SZ			0x18	/* 6 words * 4 bytes */

/*
 * FCE Request Flags (Word 2):
 *   Bit 0: Signal mode (interrupt on completion)
 *   Bit 1: Auto-POP (remove from FIFO on success)
 *   Bits 4-5: Hash algorithm (for HASH Generate command):
 *     0 = No hash
 *     1 = SHA256
 *     2 = SHA384
 *     3 = SHA512
 */
#define FCE_FLAG_SIGNAL			BIT(0)
#define FCE_FLAG_AUTOPOP		BIT(1)
#define FCE_HASH_ALGO_NONE		(0u << 4)
#define FCE_HASH_ALGO_SHA256		BIT(4)
#define FCE_HASH_ALGO_SHA384		(2u << 4)
#define FCE_HASH_ALGO_SHA512		(3u << 4)

/* Output digest sizes in bytes */
#define PRIME_HASH_DIGEST_SZ_SHA256	32
#define PRIME_HASH_DIGEST_SZ_SHA384	48
#define PRIME_HASH_DIGEST_SZ_SHA512	64

/* PRIME message construction APIs, using mailbox to communicate with FW */
int prime_load_hmac_key(void *mu_base, const uint8_t *key, size_t keylen,
			uint8_t key_slot, uint8_t sha_algo);
void prime_mac_construct(uint32_t *mu_buf, uint8_t keyslot,
			 uint32_t src_addr, size_t len,
			 uint32_t digest_addr, uint8_t sha_algo,
			 uint8_t dir, uint8_t flag, uint32_t status_addr);

/*
 * prime_hash_construct - build FCE HASH Generate MU slot buffer
 *
 * @mu_buf:      MU slot buffer pointer
 * @status_addr: inbound status address (word 1)
 * @flags:       FCE flags word (word 2): FCE_FLAG_* | FCE_HASH_ALGO_*
 * @digest_addr: inbound digest output address (word 3)
 * @input_len:   payload byte length (word 4)
 * @src_addr:    inbound input address (word 5)
 */
void prime_hash_construct(uint32_t *mu_buf,
			  uint32_t status_addr,
			  uint32_t flags,
			  uint32_t digest_addr,
			  uint32_t input_len,
			  uint32_t src_addr);

#endif /* SAB_PRIME_MAC_H */
