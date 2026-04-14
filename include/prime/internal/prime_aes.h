// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025-2026 NXP
 */

#ifndef PRIME_AES_H
#define PRIME_AES_H

#include "prime_utils.h"

typedef struct {
	const uint8_t *key;
	uint32_t keylen;
	uint8_t keyslot;
} aes_key_t;

enum crypto_cipher_algorithm {
	CRYPTO_CIPHER_AES_CBC = 1,
	CRYPTO_CIPHER_AES_ECB,
	CRYPTO_CIPHER_AES_CTR
};

enum crypto_aead_algorithm {
	CRYPTO_AEAD_AES_GCM = 4,
	CRYPTO_AEAD_AES_CCM
};

enum crypto_cipher_operation {
	CRYPTO_CIPHER_OP_DECRYPT,
	CRYPTO_CIPHER_OP_ENCRYPT
};

/* Cipher Parameters */
struct aes_op_params {
	enum crypto_cipher_algorithm algo;
	uint8_t keyslot;
	uint8_t enc;
	uint8_t *iv;
	uint16_t ivlen;
};

/* AEAD Parameters */
struct aead_op_params {
	enum crypto_aead_algorithm algo;
	uint8_t keyslot;
	uint8_t enc;
	uint8_t *iv;
	uint16_t ivlen;
	struct buf aad;
	struct buf tag;
};

prime_err_t prime_cipher_init(aes_key_t *args);

#endif
