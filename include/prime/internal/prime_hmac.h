// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025-2026 NXP
 */

#ifndef PRIME_HMAC_H
#define PRIME_HMAC_H

#include "prime_utils.h"

typedef struct {
	const uint8_t *key;
	uint32_t keylen;
	uint8_t keyslot;
	//!< keyslot, valid value 0...63.
	//!< SE library will allocate the available key_slot and
	//!< return the value in keyslot
	uint8_t sha_algo;
} hmac_key_t;

enum crypto_mac_operation {
	CRYPTO_AUTH_OP_HMAC_GEN,
	CRYPTO_AUTH_OP_HMAC_VERIFY,
	CRYPTO_AUTH_OP_SHA_GEN
};

enum crypto_sha_algorithm {
	CRYPTO_AUTH_SHA_256 = 1,
	CRYPTO_AUTH_SHA_384,
	CRYPTO_AUTH_SHA_521
};

/* Authentication Parameters */
struct mac_op_params {
	enum crypto_sha_algorithm sha_algo;
	uint8_t keyslot;
	uint8_t dir;
	struct buf digest;
};

prime_err_t prime_mac_init(prime_hdl_t service_hdl, hmac_key_t *args);

#endif
