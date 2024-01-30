// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#ifndef HSM_KEY_GENERIC_CRYPTO_H
#define HSM_KEY_GENERIC_CRYPTO_H

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_key.h"
#include "internal/hsm_key_generate.h"
#ifndef PSA_COMPLIANT
/**
 *  @defgroup group22 Key generic crypto service
 * @{
 */

/**
 * Bitmap specifying the Key generic crypto service supported properties
 */
typedef uint8_t hsm_svc_key_generic_crypto_flags_t;

/**
 * Structure specifying the Key generic crypto service member arguments
 */
typedef struct {
	hsm_hdl_t key_generic_crypto_hdl;
	//!< Key generic crypto service flow handle
	hsm_svc_key_generic_crypto_flags_t flags;
	//!< bitmap indicating the service flow properties
} open_svc_key_generic_crypto_args_t;

/**
 * Open a generic crypto service flow. \n
 * User can call this function only after having opened a session.\n
 * User must open this service in order to perform key generic cryptographic
 * operations.
 *
 * \param session_hdl handle identifying the current session.
 * \param args pointer to the structure containing the function arguments.
 * \param key_generic_crypto_hdl pointer to where the key generic cryto service
 * flow handle must be written.
 *
 * \return error code
 */
hsm_err_t hsm_open_key_generic_crypto_service(hsm_hdl_t session_hdl,
					      open_svc_key_generic_crypto_args_t *args,
					      hsm_hdl_t *key_generic_crypto_hdl);

/**
 *\addtogroup qxp_specific
 * \ref group22
 *
 * - \ref This API is not supported.
 *
 */

/**
 * Terminate a previously opened key generic service flow.
 *
 * \param key_generic_crypto_hdl handle identifying the key generic service
 * flow to be closed.
 *
 * \return error code
 */
hsm_err_t hsm_close_key_generic_crypto_service(hsm_hdl_t key_generic_crypto_hdl);

/**
 *\addtogroup qxp_specific
 * \ref group22
 *
 * - \ref This API is not supported.
 *
 */

/**
 * Bitmap specifying the Key generic crypto algorithm
 */
typedef uint8_t hsm_op_key_generic_crypto_algo_t;

/**
 * Bitmap specifying the Key generic crypto supported properties
 */
typedef uint8_t hsm_op_key_generic_crypto_flags_t;

/**
 * Structure specifying the Key generic crypto member arguments
 */
typedef struct {
	uint8_t *key;
	//!< pointer to the key to be used for the cryptographic operation
	uint8_t key_size;
	//!< length in bytes of the key
	uint8_t *iv;
	//!< pointer to the initialization vector
	uint16_t iv_size;
	//!< length in bytes of the initialization vector
	uint8_t *aad;
	//!< pointer to the additional authentication data
	uint16_t aad_size;
	//!< length in bytes of the additional authentication data
	uint8_t tag_size;
	//!< length in bytes of the tag
	hsm_op_key_generic_crypto_algo_t crypto_algo;
	//!< algorithm to be used for the cryptographic operation
	hsm_op_key_generic_crypto_flags_t flags;
	//!< bitmap specifying the cryptographic operation attributes
	uint8_t *input;
	//!< pointer to the input area\n plaintext for encryption
	//!< ciphertext + tag for decryption
	uint8_t *output;
	//!< pointer to the output area\n ciphertext + tag for encryption
	//!< plaintext for decryption if the tag is verified
	uint32_t input_size;
	//!< length in bytes of the input
	uint32_t output_size;
	//!< length in bytes of the output
} op_key_generic_crypto_args_t;

/**
 * Perform key generic crypto service operations\n
 * User can call this function only after having opened a key generic
 * crypto service flow\n
 *
 * \param key_generic_crypto_hdl handle identifying the key generic
 * cryto service flow.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_key_generic_crypto(hsm_hdl_t key_generic_crypto_hdl,
				 op_key_generic_crypto_args_t *args);

//!< Perform SM4 CCM with following characteristics:
//!< SM4 CCM where AAD supported,
//!< Tag len = {4, 6, 8, 10, 12, 14, 16} bytes,
//!< IV len = {7, 8, 9, 10, 11, 12, 13} bytes
#define HSM_KEY_GENERIC_ALGO_SM4_CCM \
	((hsm_op_key_generic_crypto_algo_t)(0x10u))
//!< Perform decryption cryptographic operation
#define HSM_KEY_GENERIC_FLAGS_DECRYPT \
	((hsm_op_key_generic_crypto_flags_t)(0u << 0))
//!< Perform encryption cryptographic operation
#define HSM_KEY_GENERIC_FLAGS_ENCRYPT \
	((hsm_op_key_generic_crypto_flags_t)(1u << 0))

/**
 *\addtogroup qxp_specific
 * \ref group22
 *
 * - \ref This API is not supported.
 *
 */

/** @} end of Key generic crypto service flow */
#endif
#endif
