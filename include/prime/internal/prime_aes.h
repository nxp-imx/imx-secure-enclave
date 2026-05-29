// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025-2026 NXP
 */

#ifndef PRIME_AES_H
#define PRIME_AES_H

/**
 * @defgroup prime_aes PRIME AES Cryptographic Operations
 * @ingroup prime_crypto
 * @brief AES cipher and AEAD operations for PRIME security services
 *
 * This module provides AES encryption/decryption capabilities including:
 * - AES cipher modes (CBC, ECB, CTR)
 * - AEAD modes (GCM, CCM)
 * - Key management and initialization
 * @{
 */

#include "prime_utils.h"

/**
 * @brief Structure describing the AES key configuration
 *
 * This structure is used to configure AES keys for cryptographic operations.
 * Keys can be provided directly or referenced via keyslot.
 */
typedef struct {
	const uint8_t *key;
	//!< Pointer to the key buffer
	uint32_t keylen;
	//!< Length of the key in bytes (16, 24, or 32 for AES-128/192/256)
	uint8_t keyslot;
	//!< Key slot identifier for hardware key storage, valid values 0...63.
	//!< SE library will allocate the available key_slot and
	//!< return the value in keyslot
} aes_key_t;

/**
 * @brief AES cipher algorithm modes
 *
 * Supported AES cipher modes for encryption and decryption operations.
 */
enum crypto_cipher_algorithm {
	CRYPTO_CIPHER_AES_CBC = 1,
	//!< AES Cipher Block Chaining mode
	CRYPTO_CIPHER_AES_ECB,
	//!< AES Electronic Codebook mode
	CRYPTO_CIPHER_AES_CTR
	//!< AES Counter mode
};

/**
 * @brief AES AEAD (Authenticated Encryption with Associated Data) algorithm modes
 *
 * Supported AEAD modes that provide both confidentiality and authenticity.
 */
enum crypto_aead_algorithm {
	CRYPTO_AEAD_AES_GCM = 4,
	//!< AES Galois/Counter Mode
	CRYPTO_AEAD_AES_CCM
	//!< AES Counter with CBC-MAC
};

/**
 * @brief Cipher operation direction
 *
 * Specifies whether the operation is encryption or decryption.
 */
enum crypto_cipher_operation {
	CRYPTO_CIPHER_OP_DECRYPT,
	//!< Decryption operation
	CRYPTO_CIPHER_OP_ENCRYPT
	//!< Encryption operation
};

/**
 * @brief AES cipher operation parameters
 *
 * Structure containing all parameters required for AES cipher operations
 * (CBC, ECB, CTR modes).
 */
struct aes_op_params {
	enum crypto_cipher_algorithm algo;
	//!< Cipher algorithm to use
	uint8_t keyslot;
	//!< Key slot identifier
	uint8_t enc;
	//!< Operation direction (0=decrypt, 1=encrypt)
	uint8_t *iv;
	//!< Pointer to initialization vector buffer
	uint16_t ivlen;
	//!< Length of initialization vector in bytes
};

/**
 * @brief AES AEAD operation parameters
 *
 * Structure containing all parameters required for AEAD operations
 * (GCM, CCM modes) including additional authenticated data and tag.
 */
struct aead_op_params {
	enum crypto_aead_algorithm algo;
	//!< AEAD algorithm to use
	uint8_t keyslot;
	//!< Key slot identifier
	uint8_t enc;
	//!< Operation direction (0=decrypt, 1=encrypt)
	uint8_t *iv;
	//!< Pointer to initialization vector/nonce buffer
	uint16_t ivlen;
	//!< Length of initialization vector in bytes
	struct buf aad;
	//!< Additional Authenticated Data buffer.\n
	//!< Known Limitation : This cannot be NULL.\n
	//!< Prime expects a valid address, else PUSH will fail
	struct buf tag;
	//!< Authentication tag buffer
};

/**
 * @brief Initialize AES cipher with the specified key
 *
 * This function initializes the AES cipher engine with the provided key
 * configuration. The key can be loaded into a hardware keyslot for
 * subsequent cryptographic operations.
 *
 * @param[in] service_hdl Handle to the PRIME service session
 * @param[in] args Pointer to AES key configuration structure
 *
 * @return PRIME_ERR_NONE on success
 * @return PRIME_ERR_INVALID_PARAM if parameters are invalid
 * @return PRIME_ERR_SERVICE_OPEN if service is not properly opened
 * @return PRIME_ERROR on other errors
 */
prime_err_t prime_cipher_init(prime_hdl_t service_hdl, aes_key_t *args);

/** @} */ /* end of prime_aes group */

#endif
