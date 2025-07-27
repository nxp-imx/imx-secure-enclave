// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#ifndef PRIME_H
#define PRIME_H

#include <stddef.h>
#include "internal/prime_hmac.h"
#include "internal/prime_aes.h"

/* Status of crypto operation */
enum crypto_op_status {
	CRYPTO_OP_SUCCESS,
	CRYPTO_OP_IN_PROGRESS,
	CRYPTO_OP_AUTH_FAILED,
	CRYPTO_OP_INVALID_ARGS,
	CRYPTO_OP_FIFO_FULL,
	CRYPTO_OP_ERROR,
};

struct buf {
	uint8_t *virt_addr;
	uint32_t phys_addr;
	uint32_t len;
};

/* PRIME crypto private session structure */
typedef struct crypto_op {
	struct buf src;
	struct buf dst;
	uint32_t req_id;
	enum crypto_op_status status;

	/* Cipher Parameters */
	struct {
		enum crypto_cipher_algorithm algo;
		uint8_t keyslot;
		uint8_t enc;
		uint8_t *iv;
		uint16_t ivlen;
	} cipher;

	/* Authentication Parameters */
	struct {
		enum crypto_auth_algorithm sha_algo;
		uint8_t keyslot;
		uint8_t dir;
		struct buf digest;
	} auth;

	/* AEAD Parameters */
	struct {
		enum crypto_aead_algorithm algo;
		uint8_t keyslot;
		uint8_t enc;
		uint8_t *iv;
		uint16_t ivlen;
		struct buf aad;
		struct buf tag;
	} aead;
} crypto_op_args_t;

#endif
