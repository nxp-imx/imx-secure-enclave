// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#ifndef FCE_AES_H
#define FCE_AES_H

#include "internal/fce_utils.h"

typedef struct {
	const uint8_t *key;
	uint32_t keylen;
	uint8_t keyslot;
} aes_key_t;

enum crypto_cipher_algorithm {
	CRYPTO_CIPHER_AES_CBC = 1,
	CRYPTO_CIPHER_AES_ECB
};

enum crypto_aead_algorithm {
	CRYPTO_AEAD_AES_GCM = 3,
	CRYPTO_AEAD_AES_CCM
};

enum crypto_cipher_operation {
	CRYPTO_CIPHER_OP_ENCRYPT,
	CRYPTO_CIPHER_OP_DECRYPT
};

fce_err_t fce_cipher_init(aes_key_t *args);

#endif
