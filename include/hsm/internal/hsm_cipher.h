// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022,2023 NXP
 */

#ifndef HSM_CIPHER_H
#define HSM_CIPHER_H

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_common_def.h"
#include "common/cipher.h"

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
	HSM_CIPHER_ONE_GO_ALGO_CTR = ALGO_CIPHER_CTR,
	//!< CTR (AES supported).
	HSM_CIPHER_ONE_GO_ALGO_CFB = ALGO_CIPHER_CFB,
	//!< CFB (AES supported).
	HSM_CIPHER_ONE_GO_ALGO_OFB = ALGO_CIPHER_OFB,
	//!< OFB (AES supported).
	HSM_CIPHER_ONE_GO_ALGO_ECB = ALGO_CIPHER_ECB_NO_PAD,
	//!< ECB no padding (AES, SM4 supported).
	HSM_CIPHER_ONE_GO_ALGO_CBC = ALGO_CIPHER_CBC_NO_PAD,
	//!< CBC no padding (AES, SM4 supported).
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
