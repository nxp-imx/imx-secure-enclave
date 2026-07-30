/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025-2026 NXP
 */

#include <stdio.h>
#include <string.h>

#include "sab_prime_api.h"
#include "sab_prime_mac.h"
#include "mu_regs.h"

void prime_mac_construct(uint32_t *mu_buf, uint8_t keyslot,
			 uint32_t src_addr, size_t len,
			 uint32_t digest_addr, uint8_t sha_algo,
			 uint8_t dir, uint8_t flag,
			 uint32_t status_addr)
{
	struct prime_msg *hdr = (struct prime_msg *)mu_buf;
	volatile uint32_t *mu_reg = (volatile uint32_t *)mu_buf;
	uint8_t command;
	uint32_t i = 1;

	if (dir == 0)
		command = PRIME_HMAC_GEN;
	else if (dir == 1)
		command = PRIME_HMAC_VERIFY;
	else if (dir == 2)
		command = PRIME_HASH;

	/* message header - packed into first word */
	PRIME_MSG_HDR_INIT(hdr, command, PRIME_AUTH_SZ);

	/* message data */
	mu_reg[i++] = status_addr;
	mu_reg[i++] = (keyslot << PRIME_KEY_SLOT_SHIFT) |
		      (sha_algo << 4) | flag;
	mu_reg[i++] = digest_addr;
	mu_reg[i++] = len;
	mu_reg[i] = src_addr;
}

/*
 * prime_hash_construct - build FCE HASH Generate MU slot buffer
 *
 * FCE HASH Generate message layout:
 *   W0: Header  (cmd=0x80, size=0x18)
 *   W1: Status Address
 *   W2: Flags   (bits[5:4]=hash_algo, bit1=AutoPOP, bit0=Signal)
 *   W3: Digest Address
 *   W4: Payload Byte Length
 *   W5: Input Address
 *
 * Hash algorithm encoding in flags bits[5:4]:
 *   FCE_HASH_ALGO_SHA256 (1<<4) = SHA256
 *   FCE_HASH_ALGO_SHA384 (2<<4) = SHA384
 *   FCE_HASH_ALGO_SHA512 (3<<4) = SHA512
 */
void prime_hash_construct(uint32_t *mu_buf,
			  uint32_t status_addr,
			  uint32_t flags,
			  uint32_t digest_addr,
			  uint32_t input_len,
			  uint32_t src_addr)
{
	struct prime_msg *hdr = (struct prime_msg *)mu_buf;
	volatile uint32_t *mu_reg = (volatile uint32_t *)mu_buf;
	uint32_t i = 1;

	/* message header - packed into first word */
	PRIME_MSG_HDR_INIT(hdr, PRIME_HASH, PRIME_AUTH_SZ);

	/* message data */
	mu_reg[i++] = status_addr;
	mu_reg[i++] = flags;
	mu_reg[i++] = digest_addr;
	mu_reg[i++] = input_len;
	mu_reg[i] = src_addr;
}

int prime_load_hmac_key(void *mu_base,
			const uint8_t *key,
			size_t keylen,
			uint8_t key_slot,
			uint8_t sha_algo)
{
	struct prime_msg msg = {0};
	int ret;

	/* message header */
	PRIME_MSG_HDR_INIT(&msg, PRIME_LOAD_HMAC_KEY_REQ, PRIME_LOAD_HMAC_KEY_REQ_SZ);

	/* message data */
	msg.data[0] = (sha_algo << 8) | key_slot;
	memcpy(&msg.data[1], key, keylen);
	msg.data[33] = crc_compute((uint32_t *)&msg, PRIME_LOAD_HMAC_KEY_REQ_SZ);

	ret = imx_mu_send_recv(mu_base, &msg, &msg);
	if (ret)
		printf("Load HMAC Key Err 0x%x", msg.data[0]);

	return ret;
}
