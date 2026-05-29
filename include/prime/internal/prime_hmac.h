// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025-2026 NXP
 */

#ifndef PRIME_HMAC_H
#define PRIME_HMAC_H

/**
 * @defgroup prime_hmac PRIME HMAC and Hash Operations
 * @ingroup prime_crypto
 * @brief HMAC generation/verification and SHA hash operations for PRIME security services
 *
 * This module provides message authentication and hashing capabilities including:
 * - HMAC generation and verification
 * - SHA-256, SHA-384, SHA-512 hash operations
 * - Key management for HMAC operations
 * @{
 */

#include "prime_utils.h"

/**
 * @brief Structure describing the HMAC key configuration
 *
 * This structure is used to configure HMAC keys for message authentication
 * operations. Keys can be provided directly or referenced via keyslot.
 */
typedef struct {
	const uint8_t *key;
	//!< Pointer to the HMAC key buffer
	uint32_t keylen;
	//!< Length of the key in bytes
	uint8_t keyslot;
	//!< Key slot identifier for hardware key storage, valid value 0...63.
	//!< SE library will allocate the available key_slot and
	//!< return the value in keyslot
	uint8_t sha_algo;
	//!< SHA algorithm to use with HMAC (from crypto_sha_algorithm enum)
} hmac_key_t;

/**
 * @brief MAC operation types
 *
 * Supported message authentication code operations including HMAC
 * generation, verification, and standalone SHA hash generation.
 */
enum crypto_mac_operation {
	CRYPTO_AUTH_OP_HMAC_GEN,
	//!< HMAC generation operation
	CRYPTO_AUTH_OP_HMAC_VERIFY,
	//!< HMAC verification operation
	CRYPTO_AUTH_OP_SHA_GEN
	//!< SHA hash generation operation (without HMAC)
};

/**
 * @brief SHA hash algorithm types
 *
 * Supported SHA (Secure Hash Algorithm) variants for hashing and HMAC operations.
 */
enum crypto_sha_algorithm {
	CRYPTO_AUTH_SHA_256 = 1,
	//!< SHA-256 algorithm (256-bit digest)
	CRYPTO_AUTH_SHA_384,
	//!< SHA-384 algorithm (384-bit digest)
	CRYPTO_AUTH_SHA_521
	//!< SHA-512 algorithm (512-bit digest)
};

/**
 * @brief MAC operation parameters
 *
 * Structure containing all parameters required for HMAC generation,
 * verification, or SHA hash operations.
 */
struct mac_op_params {
	enum crypto_sha_algorithm sha_algo;
	//!< SHA algorithm to use for the operation
	uint8_t keyslot;
	//!< Key slot identifier (for HMAC operations)
	uint8_t dir;
	//!< Operation direction/type (from crypto_mac_operation enum)
	struct buf digest;
	//!< Buffer for digest/MAC output or verification input
};

/**
 * @brief Initialize HMAC with the specified key
 *
 * This function initializes the HMAC engine with the provided key
 * configuration. The key can be loaded into a hardware keyslot for
 * subsequent HMAC operations.
 *
 * @param[in] service_hdl Handle to the PRIME service session
 * @param[in] args Pointer to HMAC key configuration structure
 *
 * @return PRIME_ERR_NONE on success
 * @return PRIME_ERR_INVALID_PARAM if parameters are invalid
 * @return PRIME_ERR_SERVICE_OPEN if service is not properly opened
 * @return PRIME_ERROR on other errors
 */
prime_err_t prime_mac_init(prime_hdl_t service_hdl, hmac_key_t *args);

/** @} */ /* end of prime_hmac group */

#endif
