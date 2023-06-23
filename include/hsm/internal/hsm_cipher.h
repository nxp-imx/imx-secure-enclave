// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022,2023 NXP
 */

#ifndef HSM_CIPHER_H
#define HSM_CIPHER_H

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_common_def.h"

#define CIPHER_OPEN_FLAGS_DEFAULT       0x0u
/**
 *  @defgroup group4 Ciphering
 * @{
 */

/**
 * Bit field describing the open cipher service requested operation
 */
typedef uint8_t hsm_svc_cipher_flags_t;
/**
 * Structure describing the open cipher service members
 */
typedef struct {
	hsm_hdl_t cipher_hdl;
	//!< handle identifying the cipher service flow
	hsm_svc_cipher_flags_t flags;
	//!< bitmap specifying the services properties
	uint8_t reserved[3];
} open_svc_cipher_args_t;

/**
 * - Open a cipher service flow.
 * - User can call this function only after having opened a key-store
 *   service flow.
 * - User must open this service in order to perform cipher operation.
 *
 * \param key_store_hdl: handle identifying the key store service flow.
 * \param args: pointer to the structure containing the function arguments.
 * \param cipher_hdl: pointer to where the cipher service flow handle
 *                    must be written.
 *
 * \return error code
 */
hsm_err_t hsm_open_cipher_service(hsm_hdl_t key_store_hdl,
				  open_svc_cipher_args_t *args,
				  hsm_hdl_t *cipher_hdl);

/**
 * Enum describing the cipher one go operation algorithm
 */
#ifdef PSA_COMPLIANT
typedef enum {
	//!< CTR (AES supported).
	HSM_CIPHER_ONE_GO_ALGO_CTR = ALGO_CIPHER_CTR,
	//!< CFB (AES supported).
	HSM_CIPHER_ONE_GO_ALGO_CFB = ALGO_CIPHER_CFB,
	//!< OFB (AES supported).
	HSM_CIPHER_ONE_GO_ALGO_OFB = ALGO_CIPHER_OFB,
	//!< ECB no padding (AES, SM4 supported).
	HSM_CIPHER_ONE_GO_ALGO_ECB = ALGO_CIPHER_ECB_NO_PAD,
	//!< CBC no padding (AES, SM4 supported).
	HSM_CIPHER_ONE_GO_ALGO_CBC = ALGO_CIPHER_CBC_NO_PAD,
} hsm_op_cipher_one_go_algo_t;

#else
typedef uint8_t hsm_op_cipher_one_go_algo_t;

#define HSM_CIPHER_ONE_GO_ALGO_AES_ECB \
				((hsm_op_cipher_one_go_algo_t)(0x00u))
#define HSM_CIPHER_ONE_GO_ALGO_AES_CBC \
				((hsm_op_cipher_one_go_algo_t)(0x01u))

//!< Perform AES CCM with following constraints:
//   - AES CCM where:
//     -- Adata = 0,
//     -- Tlen = 16 bytes,
//     -- nonce size = 12 bytes
#define HSM_CIPHER_ONE_GO_ALGO_AES_CCM \
				((hsm_op_cipher_one_go_algo_t)(0x04u))
#define HSM_CIPHER_ONE_GO_ALGO_SM4_ECB \
				((hsm_op_cipher_one_go_algo_t)(0x10u))
#define HSM_CIPHER_ONE_GO_ALGO_SM4_CBC \
				((hsm_op_cipher_one_go_algo_t)(0x11u))
#endif

/**
 * Bit field indicating the requested operations
 */
typedef uint8_t hsm_op_cipher_one_go_flags_t;
/**
 * Bit indicating the decrypt operation
 */
#define HSM_CIPHER_ONE_GO_FLAGS_DECRYPT \
				((hsm_op_cipher_one_go_flags_t)(0u << 0))
/**
 * Bit indicating the encrypt operation
 */
#define HSM_CIPHER_ONE_GO_FLAGS_ENCRYPT \
				((hsm_op_cipher_one_go_flags_t)(1u << 0))

/**
 * Structure describing the cipher one go operation arguments
 */
typedef struct {
	//!< identifier of the key to be used for the operation
	uint32_t key_identifier;
	//!< pointer to the initialization vector (nonce in case of AES CCM)
	uint8_t *iv;
	//!< length in bytes of the initialization vector.
	//   it must be 0 for algorithms not using the initialization vector.
	//   It must be 12 for AES in CCM mode
	uint16_t iv_size;
	//!< bitmap specifying the services properties.
	hsm_svc_cipher_flags_t svc_flags;
	//!< bitmap specifying the operation attributes
	hsm_op_cipher_one_go_flags_t flags;
	//!< algorithm to be used for the operation
	hsm_op_cipher_one_go_algo_t cipher_algo;
	//!< pointer to the input area:
	//   - plaintext for encryption
	//   - ciphertext for decryption
	//     Note: In case of CCM it is the purported ciphertext.
	uint8_t *input;
	//!< pointer to the output area:
	//   - ciphertext for encryption
	//     Note: In case of CCM it is the output of the
	//           generation-encryption process.
	//   - plaintext for decryption
	uint8_t *output;
	//!< length in bytes of the input.
	//   - In case of CBC and ECB, the input size should be multiple of
	//     a block cipher size (16 bytes).
	uint32_t input_size;
	//!< length in bytes of the output
	uint32_t output_size;
#ifdef PSA_COMPLIANT
	//!< expected output buffer size in bytes, valid in case of HSM_OUT_TOO_SMALL
	//   (0x1D) error code
	uint32_t exp_output_size;
#endif
} op_cipher_one_go_args_t;

/**
 * Perform ciphering operation\n
 * User can call this function only after having opened a cipher service flow
 *
 * \param cipher_hdl handle identifying the cipher service flow.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */

hsm_err_t hsm_cipher_one_go(hsm_hdl_t cipher_hdl,
			    op_cipher_one_go_args_t *args);

/**
 * Terminate a previously opened cipher service flow
 *
 * \param cipher_hdl: pointer to handle identifying the cipher service flow
 *                    to be closed.
 *
 * \return error code
 */
hsm_err_t hsm_close_cipher_service(hsm_hdl_t cipher_hdl);
#ifndef PSA_COMPLIANT
/**
 *\addtogroup qxp_specific
 * \ref group4
 *
 * - \ref HSM_CIPHER_ONE_GO_ALGO_SM4_ECB is not supported.
 * - \ref HSM_CIPHER_ONE_GO_ALGO_SM4_CBC is not supported.
 * - \ref HSM_AUTH_ENC_ALGO_SM4_CCM is not supported.
 *
 * - \ref hsm_ecies_decryption:
 *   This feature is disabled when part is running in FIPS approved mode.
 *   Any call to this API will results in a HSM_FEATURE_DISABLED error.
 *
 * - \ref hsm_key_type_t of op_ecies_dec_args_t:
 *   Only HSM_KEY_TYPE_ECDSA_NIST_P256 and HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_256
 *   are supported.
 *
 */

/**
 *\addtogroup dxl_specific
 * \ref group4
 *
 * - \ref hsm_key_type_t of op_ecies_dec_args_t:
 *   Only HSM_KEY_TYPE_ECDSA_NIST_P256 and HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_256
 *   are supported.
 *
 */
#endif
/** @} end of cipher service flow */
#endif
