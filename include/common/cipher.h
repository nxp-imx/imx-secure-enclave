// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#ifndef CIPHER_H
#define CIPHER_H

#include <stdint.h>

/**
 *  @defgroup group4 Ciphering
 * @{
 */

/**
 * Structure describing the open cipher service members
 */
typedef struct {
	uint32_t cipher_hdl;
	//!< handle identifying the cipher service flow
	uint8_t flags;
	//!< bitmap specifying the services properties
	uint8_t reserved[3];
	//!< reserved bits
} open_svc_cipher_args_t;

/**
 * Structure describing the cipher one go operation arguments
 */
typedef struct {
	uint32_t key_identifier;
	//!< identifier of the key to be used for the operation
#ifdef PSA_COMPLIANT
	//!< The flag for PLAINTEXT key must not be set.
	uint8_t *key;
	//!< pointer to the plaintext key buffer.
	//!< The flag for PLAINTEXT key must be set.
	//!< Only valid for INIT and ONE SHOT operations.
#endif
	uint8_t *iv;
	//!< pointer to the initialization vector (nonce in case of AES CCM)
#ifdef PSA_COMPLIANT
	//!< Only valid for INIT and ONE SHOT operations
#endif
	uint16_t iv_size;
	//!< length in bytes of the initialization vector.
	//!< it must be 0 for algorithms not using the initialization vector.
#ifdef PSA_COMPLIANT
	//!< CBC, CTR, OFB, CFB size is fixed to 16 bytes.
	//!< Only valid for INIT and ONE SHOT operations
#else
	//!< It must be 12 for AES in CCM mode (not valid for SHE)
#endif
	uint8_t svc_flags;
	//!< bitmap specifying the services properties.
#ifdef PSA_COMPLIANT
	uint16_t flags;
	//!< bitmap specifying the operation attributes.
	//!< One-Shot operation configured, if none of bits 8, 10, 11, 15 are set
	uint32_t cipher_algo;
#else
	uint8_t flags;
	//!< bitmap specifying the operation attributes
	uint8_t cipher_algo;
#endif
	//!< algorithm to be used for the operation
	uint8_t *input;
	//!< pointer to the input area:
	//!< - plaintext for encryption
	//!< - ciphertext for decryption
#ifdef PSA_COMPLIANT
	//!< Only valid with ONE SHOT or UPDATE DATA
#else
	//!<   Note: In case of CCM it is the purported ciphertext.
#endif
	uint8_t *output;
	//!< pointer to the output area:
	//!< - ciphertext for encryption
	//!<   Note: In case of CCM it is the output of the
	//!<         generation-encryption process.
	//!< - plaintext for decryption
#ifdef PSA_COMPLIANT
	//!< Only valid with ONE SHOT or UPDATE DATA or FINALIZE.
#endif
	uint32_t input_size;
	//!< length in bytes of the input.
	//!< - In case of CBC and ECB, the input size should be multiple of
	//!<   a block cipher size (16 bytes).
#ifdef PSA_COMPLIANT
	//!< Only valid with valid with ONE SHOT or UPDATE DATA.
#endif
	uint32_t output_size;
	//!< length in bytes of the output
#ifdef PSA_COMPLIANT
	//!< Only valid with ONE SHOT or UPDATE DATA.
	uint16_t key_size;
	//!< Key size in bytes. Only valid with PLAINTEXT flag.
	//!< Only valid with ONE SHOT or INIT operations.
	uint16_t key_type;
	//!< Key type. Only valid with PLAINTEXT flag.
	//!< Only valid with ONE SHOT or INIT operations.
	uint8_t *context;
	//!< Context buffer. Only valid with PLAINTEXT flag.
	uint16_t context_size;
	//!< Size in Bytes of context buffer. Only valid with PLAINTEXT flag.
	uint32_t exp_output_size;
	//!< Expected output buffer size in bytes, valid in case of (0x1D) error code.
	//!< Expected context buffer size in bytes, valid in case of (0x1E) error code.
#endif
} op_cipher_one_go_args_t;

/**
 * Structure describing the cipher operation arguments
 */
typedef op_cipher_one_go_args_t op_cipher_args_t;

/** @} end of cipher service flow */
#endif
