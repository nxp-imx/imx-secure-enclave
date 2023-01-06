/*
 * Copyright 2023 NXP
 *
 * NXP Confidential.
 * This software is owned or controlled by NXP and may only be used strictly
 * in accordance with the applicable license terms.  By expressly accepting
 * such terms or by downloading, installing, activating and/or otherwise using
 * the software, you are agreeing that you have read, and that you agree to
 * comply with and are bound by, such license terms.  If you do not agree to be
 * bound by the applicable license terms, then you may not retain, install,
 * activate or otherwise use the software.
 */

#ifndef HSM_AUTH_ENC_H
#define HSM_AUTH_ENC_H

#include "internal/hsm_common_def.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_handle.h"

#ifdef PSA_COMPLIANT
typedef enum {
	//!< CCM (AES CCM)
	HSM_AEAD_ALGO_CCM = ALGO_CCM,
} hsm_op_auth_enc_algo_t;

#else
typedef uint8_t hsm_op_auth_enc_algo_t;

//!< Perform AES GCM with following constraints:
//	 AES GCM where AAD supported, Tag len = 16 bytes, IV len = 12 bytes
#define HSM_AUTH_ENC_ALGO_AES_GCM \
			((hsm_op_auth_enc_algo_t)(0x00u))

//!< Perform SM4 CCM with following constraints:
//	 SM4 CCM where AAD supported, Tag len = 16 bytes, IV len = 12 bytes
#define HSM_AUTH_ENC_ALGO_SM4_CCM \
			((hsm_op_auth_enc_algo_t)(0x10u))
#endif

typedef uint8_t hsm_op_auth_enc_flags_t;

#define HSM_AUTH_ENC_FLAGS_DECRYPT \
			((hsm_op_auth_enc_flags_t)(0u << 0))
#define HSM_AUTH_ENC_FLAGS_ENCRYPT \
			((hsm_op_auth_enc_flags_t)(1u << 0))
//!< Full IV is internally generated (only relevant for encryption)
#define HSM_AUTH_ENC_FLAGS_GENERATE_FULL_IV \
			((hsm_op_auth_enc_flags_t)(1u << 1))
//!< User supplies 4 bytes of the IV (fixed part), the other bytes are
//	 internally generated (only relevant for encryption)
#define HSM_AUTH_ENC_FLAGS_GENERATE_COUNTER_IV \
			((hsm_op_auth_enc_flags_t)(1u << 2))

typedef struct {
	//!< identifier of the key to be used for the operation
	uint32_t key_identifier;
	//!< pointer to the user supplied part of initialization vector or nonce,
	//	 when applicable, otherwise 0
	uint8_t *iv;
	//!< length in bytes of the fixed part of the initialization vector for
	//	 encryption (0 or 4 bytes), length in bytes of the full IV for
	//	 decryption (12 bytes)
	uint16_t iv_size;
	//!< pointer to the additional authentication data
	uint8_t *aad;
	//!< length in bytes of the additional authentication data
	uint16_t aad_size;
	//!< algorithm to be used for the operation
	hsm_op_auth_enc_algo_t ae_algo;
	//!< bitmap specifying the operation attributes
	hsm_op_auth_enc_flags_t flags;
	//!< pointer to the input area\n plaintext for encryption\n
	//	 Ciphertext + Tag (16 bytes) for decryption
	uint8_t *input;
	//!< pointer to the output area\n Ciphertext + Tag (16 bytes)
	//	 + IV for encryption\n plaintext for decryption if the Tag is verified
	uint8_t *output;
	//!< length in bytes of the input
	uint32_t input_size;
	//!< length in bytes of the output
	uint32_t output_size;
} op_auth_enc_args_t;

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
 */
hsm_err_t hsm_auth_enc(hsm_hdl_t cipher_hdl, op_auth_enc_args_t *args);
#endif