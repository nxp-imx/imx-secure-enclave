// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2024, 2026 NXP
 */

#ifndef HSM_CIPHER_H
#define HSM_CIPHER_H

#include "hsm_handle.h"
#include "hsm_utils.h"
#include "hsm_common_def.h"
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

#ifdef PSA_COMPLIANT
/**
 * Enum describing the cipher one go operation algorithm
 */
typedef enum {
	HSM_CIPHER_ONE_GO_ALGO_CTR = ALGO_CIPHER_CTR,
	//!< CTR (AES supported).
	HSM_CIPHER_ONE_GO_ALGO_CFB = ALGO_CIPHER_CFB,
	//!< CFB (AES supported).
	HSM_CIPHER_ONE_GO_ALGO_OFB = ALGO_CIPHER_OFB,
	//!< OFB (AES supported).
	HSM_CIPHER_ONE_GO_ALGO_ECB = ALGO_CIPHER_ECB_NO_PAD,
	//!< ECB no padding (AES supported).
	HSM_CIPHER_ONE_GO_ALGO_CBC = ALGO_CIPHER_CBC_NO_PAD,
	//!< CBC no padding (AES supported).
} hsm_op_cipher_one_go_algo_t;

/**
 * Enum describing the cipher operation algorithm
 */
typedef enum {
	HSM_CIPHER_ALGO_CTR = ALGO_CIPHER_CTR,
	//!< CTR (AES supported).
	HSM_CIPHER_ALGO_CFB = ALGO_CIPHER_CFB,
	//!< CFB (AES supported).
	HSM_CIPHER_ALGO_OFB = ALGO_CIPHER_OFB,
	//!< OFB (AES supported).
	HSM_CIPHER_ALGO_ECB = ALGO_CIPHER_ECB_NO_PAD,
	//!< ECB no padding (AES supported).
	HSM_CIPHER_ALGO_CBC = ALGO_CIPHER_CBC_NO_PAD,
	//!< CBC no padding (AES supported).
} hsm_op_cipher_algo_t;
#else
/**
 * Enum describing the cipher one go operation algorithm
 */
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

#ifdef PSA_COMPLIANT
/**
 * Bit field indicating the requested operations
 */
typedef uint16_t hsm_op_cipher_one_go_flags_t;
typedef hsm_op_cipher_one_go_flags_t hsm_op_cipher_flags_t;
#else
/**
 * Bit field indicating the requested operations
 */
typedef uint8_t hsm_op_cipher_one_go_flags_t;
#endif

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

#ifdef PSA_COMPLIANT
/**
 * Bit indicating the decrypt operation
 */
#define HSM_CIPHER_FLAGS_DECRYPT \
			((hsm_op_cipher_flags_t)(0u << 0))
/**
 * Bit indicating the encrypt operation
 */
#define HSM_CIPHER_FLAGS_ENCRYPT \
			((hsm_op_cipher_flags_t)(1u << 0))

/**
 * Bit indicating the PLAINTEXT key user input
 */
#define HSM_CIPHER_FLAGS_PLAINTEXT_KEY \
			((hsm_op_cipher_flags_t)(1u << 3))

/**
 * Bit indicating INIT for a multipart context
 */
#define HSM_CIPHER_FLAGS_INIT \
			((hsm_op_cipher_flags_t)(1u << 8))

/**
 * Bit indicating UPDATE DATA to be encrypted/decrypted
 */
#define HSM_CIPHER_FLAGS_UPDATE_DATA \
			((hsm_op_cipher_flags_t)(1u << 10))

/**
 * Bit indicating FINALIZE the multipart operation
 */
#define HSM_CIPHER_FLAGS_FINALIZE \
			((hsm_op_cipher_flags_t)(1u << 11))

/**
 * Bit indicating ABORT for a multipart operation and clean the context
 */
#define HSM_CIPHER_FLAGS_ABORT \
			((hsm_op_cipher_flags_t)(1u << 13))

/**
 * Bit indicating GET CTX SIZE.
 * Size of needed allocated context is returned in Output size response field.
 */
#define HSM_CIPHER_FLAGS_GET_CTX_SIZE \
			((hsm_op_cipher_flags_t)(1u << 15))
#endif

#ifdef PSA_COMPLIANT
/**
 * Perform ciphering operation\n
 *   - One-Shot cipher operation using an opaque or plaintext key
 *   - Streaming cipher operation using an opaque or plaintext key
 *
 * User can call this function only after having opened a cipher service flow
 *
 * \param cipher_hdl handle identifying the cipher service flow.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
#else
/**
 * Perform ciphering operation\n
 * User can call this function only after having opened a cipher service flow
 *
 * \param cipher_hdl handle identifying the cipher service flow.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
#endif
hsm_err_t hsm_cipher(hsm_hdl_t cipher_hdl, op_cipher_args_t *args);

/**
 * Perform ciphering operation\n
 * User can call this function only after having opened a cipher service flow
 *
 * \param cipher_hdl handle identifying the cipher service flow.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 *
 * Note: This API will be deprecated soon.
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
