// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#ifndef HSM_AUTH_ENC_H
#define HSM_AUTH_ENC_H

#include "internal/hsm_common_def.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_handle.h"

/**
 *  @defgroup group4 Ciphering
 * @{
 */

/**
 * Bit field indicating the supported algorithm
 */
#ifdef PSA_COMPLIANT
typedef enum {
	HSM_AEAD_ALGO_CCM = ALGO_CCM,
	//!< CCM (AES CCM)
	HSM_AEAD_ALGO_GCM = ALGO_GCM,
	//!< GCM (AES GCM)
	HSM_AEAD_ALGO_CHACHA20_POLY1305 = ALGO_CHACHA20_POLY1305,
	//!< CHACHA20_POLY1305
	HSM_AEAD_ALGO_ALL_AEAD = ALGO_ALL_AEAD,
	//!< ALL AEAD (ALL AEAD)
} hsm_op_auth_enc_algo_t;

#else
typedef uint8_t hsm_op_auth_enc_algo_t;

//!< Perform AES GCM with following constraints:
//!<	 AES GCM where AAD supported, Tag len = 16 bytes, IV len = 12 bytes
#define HSM_AUTH_ENC_ALGO_AES_GCM \
			((hsm_op_auth_enc_algo_t)(0x00u))

//!< Perform SM4 CCM with following constraints:
//!<	 SM4 CCM where AAD supported, Tag len = 16 bytes, IV len = 12 bytes
#define HSM_AUTH_ENC_ALGO_SM4_CCM \
			((hsm_op_auth_enc_algo_t)(0x10u))
#endif

/**
 * Bit field indicating the authenticated encryption operations
 */
typedef uint8_t hsm_op_auth_enc_flags_t;

#ifdef PSA_COMPLIANT
/**
 * Bit field indicating the authenticated encryption operations
 */
typedef uint16_t hsm_op_auth_enc_new_flags_t;
#endif

/**
 * Bit indicating the decryption operation
 */
#define HSM_AUTH_ENC_FLAGS_DECRYPT \
			((hsm_op_auth_enc_flags_t)(0u << 0))
/**
 * Bit indicating the encryption operation
 */
#define HSM_AUTH_ENC_FLAGS_ENCRYPT \
			((hsm_op_auth_enc_flags_t)(1u << 0))
/**
 * Bit indicating the Full IV is internally generated (only relevant for encryption)
 */
#define HSM_AUTH_ENC_FLAGS_GENERATE_FULL_IV \
			((hsm_op_auth_enc_flags_t)(1u << 1))
/**
 * Bit indicating 4 bytes supplied other bytes internally generated (only relevant for encryption)
 */
#define HSM_AUTH_ENC_FLAGS_GENERATE_COUNTER_IV \
			((hsm_op_auth_enc_flags_t)(1u << 2))
#ifdef PSA_COMPLIANT
/**
 * Bit indicating PLAINTEXT key user input
 */
#define HSM_AUTH_ENC_FLAGS_PLAINTEXT_KEY \
			((hsm_op_auth_enc_new_flags_t)(1u << 3))
/**
 * Bit indicating ONE SHOT operation
 */
#define HSM_AUTH_ENC_FLAGS_ONE_SHOT \
			((hsm_op_auth_enc_new_flags_t)(1u << 4))
/**
 * Bit indicating INIT operation. Init a multipart context.
 */
#define HSM_AUTH_ENC_FLAGS_INIT \
			((hsm_op_auth_enc_new_flags_t)(1u << 8))
/**
 * Bit indicating UPDATE AAD operation. Update additional authenticated data
 */
#define HSM_AUTH_ENC_FLAGS_UPDATE_AAD \
			((hsm_op_auth_enc_new_flags_t)(1u << 9))
/**
 * Bit indicating UPDATE DATA operation. Update data to be encrypted/decrypted
 */
#define HSM_AUTH_ENC_FLAGS_UPDATE_DATA \
			((hsm_op_auth_enc_new_flags_t)(1u << 10))
/**
 * Bit indicating FINALIZE operation. Tag will be outputted in buffer
 */
#define HSM_AUTH_ENC_FLAGS_FINALIZE \
			((hsm_op_auth_enc_new_flags_t)(1u << 11))
/**
 * Bit indicating FINALIZE VERIFY operation. Tag is compared internally with
 * the one provided in Tag buffer. Valid only for decryption.
 */
#define HSM_AUTH_ENC_FLAGS_FINALIZE_VERIFY \
			((hsm_op_auth_enc_flags_t)(1u << 12))
/**
 * Bit indicating ABORT operation. Abort a multipart operation and clean the
 * context.
 */
#define HSM_AUTH_ENC_FLAGS_ABORT \
			((hsm_op_auth_enc_new_flags_t)(1u << 13))
/**
 * Bit indicating GET CTX SIZE operation. Size of needed allocated context.
 * Return in Output size response field.
 */
#define HSM_AUTH_ENC_FLAGS_GET_CTX_SIZE \
			((hsm_op_auth_enc_new_flags_t)(1u << 15))

/**
 *  Bit indicating the Authenticated Encryption (New) response verification status
 */
typedef uint32_t hsm_aead_verification_status_t;

/**
 * Authenticated Encryption response verification status success
 */
#define HSM_AEAD_VERIFICATION_STATUS_SUCCESS \
			((hsm_aead_verification_status_t)(0x5A3CC3A5u))
/**
 * Authenticated Encryption response verification status failure
 */
#define HSM_AEAD_VERIFICATION_STATUS_FAILURE \
			((hsm_aead_verification_status_t)(0x2B4DD4B2u))
#endif

/**
 * Structure describing the authenticated encryption operation arguments
 */
typedef struct {
	uint32_t key_identifier;
	//!< identifier of the key to be used for the operation
	uint8_t *iv;
	//!< pointer to the user supplied part of initialization vector or nonce,
	//!<	 when applicable, otherwise 0
	uint16_t iv_size;
	//!< length in bytes of the fixed part of the initialization vector for
	//!<	 encryption (0 or 4 bytes), length in bytes of the full IV for
	//!<	 decryption (12 bytes)
	uint8_t *aad;
	//!< pointer to the additional authentication data
	uint16_t aad_size;
	//!< length in bytes of the additional authentication data
	hsm_op_auth_enc_algo_t ae_algo;
	//!< algorithm to be used for the operation
	hsm_op_auth_enc_flags_t flags;
	//!< bitmap specifying the operation attributes
	uint8_t *input;
	//!< pointer to the input area\n plaintext for encryption\n
	//!<	 Ciphertext + Tag (16 bytes) for decryption
	uint8_t *output;
	//!< pointer to the output area\n Ciphertext + Tag (16 bytes)
	//!<	 + IV for encryption\n plaintext for decryption if the Tag is verified
	uint32_t input_size;
	//!< length in bytes of the input
	uint32_t output_size;
	//!< length in bytes of the output
#ifdef PSA_COMPLIANT
	uint32_t exp_output_size;
	//!< expected output buffer size in bytes, valid in case of HSM_OUT_TOO_SMALL
	//!<   (0x1D) error code
#endif
} op_auth_enc_args_t;

#ifdef PSA_COMPLIANT
/**
 * It indicates the size (in bytes) of the IV output buffer,received with the
 * response of Authenticated Encryption operation. Valid only if flag is set for:
 *   - HSM_AUTH_ENC_FLAGS_GENERATE_FULL_IV, or
 *   - HSM_AUTH_ENC_FLAGS_GENERATE_COUNTER_IV
 */
#define HSM_AUTH_ENC_IV_OUT_SIZE (12)

/**
 * Structure describing the authenticated encryption (new) operation arguments
 */
typedef struct {
	hsm_op_auth_enc_algo_t ae_algo;
	//!< algorithm to be used for the operation
	hsm_op_auth_enc_new_flags_t flags;
	//!< bitmap specifying the operation attributes
	uint32_t key_id;
	//!< identifier of the key. Only valid with INIT or ONE SHOT.
	//!< PLAINTEXT key flag must not be set.
	uint8_t *key;
	//!< PLAINTEXT key to be used for operation.
	//!< Only valid with INIT or ONE SHOT and PLAINTEXT key flag.
	uint16_t key_size;
	//!< Size in Bytes of Key. Only needed for ONE SHOT or INIT with PLAINTEXT
	uint16_t key_type;
	//!< Key Type attribute. Only needed for ONE SHOT or INIT with PLAINTEXT
	uint16_t iv_size;
	//!< IV size in bytes
	//!< CCM: Must be 12 bytes
	//!< GCM: following are the possible input sizes:
	//!<   - 0 when the Full IV is internally generated (Bit 1 flag)
	//!<   - 4 when the Counter IV generation option is used (Bit 2 flag)
	//!<   - 12 when the IV is entirely generated by the user
	uint8_t *iv_in;
	//!< pointer to the user input IV (or nonce) when applicable, otherwise 0
	//!< Only valid with INIT or ONE SHOT
	uint8_t *iv_out;
	//!< IV (or nonce) output if generated randomly by ELE, depends on flags.
	//!< Only valid with INIT or ONE SHOT and IV generated by ELE (Bit 1 or
	//!< Bit 2 flag).
	//!< 12 bytes in size. User responsible to free the buffer after usage.
	uint8_t *tag;
	//!< Depending on the operation, usage is different:
	//!<   - Encrypt: Output buffer for the tag
	//!<   - Decrypt: ONE SHOT or FINALIZE VERIFY: Input tag buffer to be verified
	//!<   - Decrypt: FINALIZE: output buffer where the tag is outputted
	//!< Only valid with FINALIZE (output) or FINALIZE VERIFY (input) or ONE SHOT
	uint16_t tag_size;
	//!< Size in Bytes of Tag buffer. Must be at least 16 bytes, if applicable.
	//!< Only valid with FINALIZE or FINALIZE VERIFY or ONE SHOT
	uint8_t *aad;
	//!< pointer to the additional authentication data, if applicable.
	//!< Only valid with ONE SHOT or UPDATE AAD
	uint32_t aad_size;
	//!< Size in Bytes of AAD.
	//!< Must be set to valid value during init phase for AES CCM algo.
	//!< Must be set to 0 for other algorithm init phase.
	//!< Only valid with ONE SHOT or UPDATE AAD
	uint8_t *input;
	//!< pointer to the input area.
	//!< Depending on the operation, signification is different:
	//!<   - Encrypt: Plaintext to encrypt
	//!<   - Decrypt: Ciphertext to decrypt
	//!< This field is valid with ONE SHOT or UPDATE DATA
	uint32_t input_size;
	//!< Size in Bytes of Input data.
	//!< Must be set to valid value during init phase for AES CCM algo.
	//!< Must be set to 0 for other algorithm init phase.
	//!< Only valid with ONE SHOT or UPDATE DATA
	uint8_t *output;
	//!< pointer to the output area.
	//!< Depending on the operation, signification is different:
	//!<   - Encrypt: Ciphertext
	//!<   - Decrypt: Plaintext
	//!< Only valid with ONE SHOT or UPDATE DATA or FINALIZE or FINALIZE VERIFY
	uint32_t output_size;
	//!< length in bytes of the output.
	//!< Only valid with ONE SHOT or UPDATE DATA or FINALIZE or FINALIZE VERIFY
	uint8_t *context;
	//!< Input context buffer. Only valid with PLAINTEXT key.
	uint16_t context_size;
	//!< Size in Bytes of context buffer. Only valid with PLAINTEXT key.
	uint32_t exp_output_size;
	//!< Expected output buffer size in bytes, valid in case of HSM_OUT_TOO_SMALL
	//!< (0x1D) error code.
	//!< In case of streaming operation, Expected context size in bytes if
	//1< operation failed with 0x1E.
	hsm_aead_verification_status_t verify_status;
	//!< Verification status.
} op_auth_enc_new_args_t;
#endif

/**
 * Perform authenticated encryption operation\n
 * User can call this function only after having opened a cipher service flow\n
 *
 * For decryption operations, the full IV is supplied by the caller via
 * the iv and iv_size parameters. HSM_AUTH_ENC_FLAGS_GENERATE_FULL_IV and
 * HSM_AUTH_ENC_FLAGS_GENERATE_COUNTER_IV flags are ignored.\n
 *
 * For encryption operations, either HSM_AUTH_ENC_FLAGS_GENERATE_FULL_IV or
 * HSM_AUTH_ENC_FLAGS_GENERATE_COUNTER_IV must be set when calling this function:
 * - When HSM_AUTH_ENC_FLAGS_GENERATE_FULL_IV is set, the full IV is internally
 *	 generated, iv and iv_size must be set to 0
 * - When HSM_AUTH_ENC_FLAGS_GENERATE_COUNTER_IV is set, the user supplies
 *	 a 4 byte fixed part of the IV. The other IV bytes are internally generated
 *
 * \param cipher_hdl handle identifying the cipher service flow.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 *
 * Note: The API is deprecated now.
 */
hsm_err_t hsm_auth_enc(hsm_hdl_t cipher_hdl, op_auth_enc_args_t *args);

#ifdef PSA_COMPLIANT
/**
 * Perform authenticated encryption operation (NEW)\n
 *   - One-Shot AEAD operation using an opaque or plaintext key.
 *   - Streaming AEAD operation using an opaque or plaintext key.
 *
 * User can call this function only after having opened a cipher service flow\n
 *
 * \param cipher_hdl handle identifying the cipher service flow.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_auth_enc_new(hsm_hdl_t cipher_hdl, op_auth_enc_new_args_t *args);
#endif
/** @} end of cipher service flow */
#endif
