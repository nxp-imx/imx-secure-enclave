// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025-2026 NXP
 */

#ifndef HSM_ASYMMETRIC_CRYPTO_H
#define HSM_ASYMMETRIC_CRYPTO_H

#include "hsm_utils.h"
#include "hsm_handle.h"
#include "hsm_common_def.h"

/**
 * @defgroup group38 Asymmetric Crypto Encryption
 * @{
 */

#ifdef PSA_COMPLIANT

/**
 * Bit indicating the decrypt operation
 */
#define HSM_ASYM_FLAGS_DECRYPT		(0u << 1)

/**
 * Bit indicating the encrypt operation
 */
#define HSM_ASYM_FLAGS_ENCRYPT		BIT(0)

/**
 * Bit indicating the PLAINTEXT key user input
 */
#define HSM_ASYM_FLAGS_PLAINTEXT_KEY	BIT(3)

/**
 * Bit indicating the OPAQUE key user input
 */
#define HSM_ASYM_FLAGS_OPAQUE_KEY	(0u << 3)

/**
 * Enum describing the asymmetric operation algorithm
 */
typedef enum {
	HSM_ASYM_ALGO_RSA_PKCS1_V15_CRYPT = ALGO_RSA_PKCS1_V15_CRYPT,
	HSM_ASYM_ALGO_RSA_PKCS1_OAEP_SHA1 = ALGO_RSA_PKCS1_OAEP_SHA1,
	HSM_ASYM_ALGO_RSA_PKCS1_OAEP_SHA224 = ALGO_RSA_PKCS1_OAEP_SHA224,
	HSM_ASYM_ALGO_RSA_PKCS1_OAEP_SHA256 = ALGO_RSA_PKCS1_OAEP_SHA256,
	HSM_ASYM_ALGO_RSA_PKCS1_OAEP_SHA384 = ALGO_RSA_PKCS1_OAEP_SHA384,
	HSM_ASYM_ALGO_RSA_PKCS1_OAEP_SHA512 = ALGO_RSA_PKCS1_OAEP_SHA512,
} hsm_op_asymmetric_algo_t;

/**
 * Structure representing the Asymmetric Encryption Open (0x90) command.
 *
 * This command is used to open an asymmetric encryption service flow
 * on a specified key store.\n
 * It is only available at runtime in the EdgeLock Secure Enclave Firmware.
 */
typedef struct {
	uint32_t key_store_handle;
	//!< Handle identifying the key store service flow.
	uint32_t input_pointer_msb;
	//!< Most significant 32 bits of the input pointer address.
	//!< Must be set to 0x0. 64-bit addressing is not supported yet.
	uint32_t output_pointer_msb;
	//!< Most significant 32 bits of the output pointer address.
	//!< Must be set to 0x0. 64-bit addressing is not supported yet.
	uint8_t flags;
	//!< Flags : reserved for future use
	uint32_t asymmetric_enc_handle;
	//!< Asymmetric encryption handle returned by the API.
} op_asymmetric_enc_open_args_t;

/**
 * Structure representing the Asymmetric Encryption Command API.
 */
typedef struct {
	uint32_t asymmetric_enc_handle;
	//!< OPAQUE KEY: Handle identifying the Asymmetric encryption service flow.
	//!< PLAINTEXT KEY: Reserved.
	uint32_t key_id;
	//!< OPAQUE KEY: Key identifier of the key to be used for the operation.
	uint8_t *key_addr;
	//!< PLAINTEXT KEY: Private or public key address (LSB).
	//!< Encryption: Public key buffer must be filled with the modulus only
	//!< (default public exponent is used by EdgeLock Secure Enclave Firmware).\n
	//!< Decryption: Private key buffer must be filled with the
	//!< concatenation of the private exponent followed by the modulus.
	uint8_t *plaintext_addr;
	//!< LSB address of the plaintext in requestor space.
	uint8_t *ciphertext_addr;
	//!< LSB address of the ciphertext in requestor space.
	uint8_t *label_addr;
	//!< LSB address of the label (optional, only for RSA PKCS1 OAEP).
	uint32_t plaintext_size;
	//!< Size of the plaintext in bytes.
	uint32_t ciphertext_size;
	//!< Size of the ciphertext in bytes.
	uint32_t label_size;
	//!< Size of the label in bytes.
	uint8_t flags;
	//!< Bit field indicating requested operations.
	//!< Bit 0: 0 = Decryption, 1 = Encryption.
	//!< Bit 3: 0 = Opaque key, 1 = Plaintext key.
	hsm_asymmetric_crypto_algo_t algorithm;
	//!< Encryption algorithm to use.
	uint32_t input_plainkey_size;
	//!< PLAINTEXT KEY ONLY: Input plaintext key size in bytes.
	uint16_t input_plainkey_type;
	//!< PLAINTEXT KEY ONLY: Input plaintext key type.
	uint16_t input_plainkey_security_size;
	//!< PLAINTEXT KEY ONLY: Input plaintext key security size in bits.
	uint32_t exp_plaintext_size;
	//!< For decryption operation, plaintext size can’t be known in advance
	//!< Operation can be called with output plaintext size set to 0.
	//!< In that case, 0x1D29 error is returned with maximum plaintext size.
	//!< Setting an invalid size (smaller than expected) will result in 0x1D29
	//!< error and expected size will be returned.
	uint32_t exp_ciphertext_size;
	//!< For encryption operation, ciphertext size is not known in advance.
	//!< Setting an invalid size (smaller than expected) will result in 0x1D29 error
	//!< and expected size will be returned.
} op_asymmetric_enc_args_t;

/**
 * This command is designed to open Asymmetric crypto service flow
 *
 * \param session_hdl handle identifying the current session.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_asymmetric_enc_open(hsm_hdl_t session_hdl,
				  op_asymmetric_enc_open_args_t *args);

/**
 * This command is designed to close Asymmetric crypto service flow
 *
 * \param asymmetric_encryption_handle handle identifying the Asymmetric service flow.
 *
 * \return error code
 */
hsm_err_t hsm_asymmetric_enc_close(hsm_hdl_t asymmetric_encryption_handle);
/**
 * This command is designed to perform the Asymmetric encryption/decryption
 *
 * \param session_hdl handle identifying the current session.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_asymmetric_enc(hsm_hdl_t session_hdl, op_asymmetric_enc_args_t *args);
/** @} end of asymmetric crypto service flow */

#endif
#endif
