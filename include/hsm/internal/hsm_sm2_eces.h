// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#ifndef HSM_SM2_ECES_H
#define HSM_SM2_ECES_H

#include "internal/hsm_common_def.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_handle.h"
#include "internal/hsm_key.h"
#ifndef PSA_COMPLIANT
/**
 *  @defgroup group18 SM2 ECES
 * @{
 */

/**
 * Bitmap specifying the sm2 eces open service supported properties
 */
typedef uint8_t hsm_svc_sm2_eces_flags_t;

/**
 * Structure specifying the sm2 eces open service member arguments
 */
typedef struct {
	hsm_hdl_t sm2_eces_hdl;
	//!< handle identifying the sm2 eces service flow
	hsm_svc_sm2_eces_flags_t flags;
	//!< bitmap indicating the service flow properties
} open_svc_sm2_eces_args_t;

/**
 * Open a SM2 ECES decryption service flow\n
 * User can call this function only after having opened a key store.\n
 * User must open this service in order to perform SM2 decryption.
 *
 * \param key_store_hdl handle identifying the key store service flow.
 * \param args pointer to the structure containing the function arguments.
 * \param sm2_eces_hdl pointer to where the sm2 eces service flow handle must be written.
 *
 * \return error code
 */
hsm_err_t hsm_open_sm2_eces_service(hsm_hdl_t key_store_hdl,
				    open_svc_sm2_eces_args_t *args,
				    hsm_hdl_t *sm2_eces_hdl);

/**
 * Terminate a previously opened SM2 ECES service flow
 *
 * \param sm2_eces_hdl handle identifying the SM2 ECES service flow to be closed.
 *
 * \return error code
 */
hsm_err_t hsm_close_sm2_eces_service(hsm_hdl_t sm2_eces_hdl);

/**
 * Bitmap specifying the sm2 eces decryption supported properties
 */
typedef uint8_t hsm_op_sm2_eces_dec_flags_t;

/**
 * Structure specifying the sm2 eces decryption member arguments
 */
typedef struct {
	uint32_t key_identifier;
	//!< identifier of the private key to be used for the operation
	uint8_t *input;
	//!< pointer to the input ciphertext
	uint8_t *output;
	//!< pointer to the output area where the plaintext must be written
	uint32_t input_size;
	//!< length in bytes of the input ciphertext.
	uint32_t output_size;
	//!< length in bytes of the output plaintext
	hsm_key_type_t key_type;
	//!< Indicates the type of the used key.
	//!< Only HSM_KEY_TYPE_DSA_SM2_FP_256 is supported.
	hsm_op_sm2_eces_dec_flags_t flags;
	//!< bitmap specifying the operation attributes.
} op_sm2_eces_dec_args_t;

/**
 * Decrypt data usign SM2 ECES \n
 * User can call this function only after having opened a SM2 ECES service flow.\n
 * SM2 ECES is supported with the requirements specified in the GB/T 32918.4.
 *
 * \param sm2_eces_hdl handle identifying the SM2 ECES
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_sm2_eces_decryption(hsm_hdl_t sm2_eces_hdl,
				  op_sm2_eces_dec_args_t *args);

/**
 *\addtogroup qxp_specific
 * \ref group18
 *
 * - \ref All the APIs related the SM2 ECES decryption are not supported.
 *
 */
/**
 *\addtogroup dxl_specific
 * \ref group18
 *
 * - \ref The output_size should be a multiple of 4 bytes.
 *
 */

/**
 * Bitmap specifying the sm2 eces encryption supported properties
 */
typedef uint8_t hsm_op_sm2_eces_enc_flags_t;

/**
 * Structure specifying the sm2 eces encryption member arguments
 */
typedef struct {
	uint8_t *input;
	//!< pointer to the input plaintext
	uint8_t *output;
	//!< pointer to the output area where the ciphertext must be written
	uint8_t *pub_key;
	//!< pointer to the input recipient public key
	uint32_t input_size;
	//!< length in bytes of the input plaintext
	uint32_t output_size;
	//!< Length in bytes of the output ciphertext.
	//!< It should be at sum of:
	//!< - least input_size,
	//!< - 97 bytes (overhead related to C1 and C3 - as specified below), and
	//!< - size alignment constraints specific to a given implementation.
	//!<
	//!< See related chapter for more details.
	uint16_t pub_key_size;
	//!< length in bytes of the recipient public key should be equal to 64 bytes
	hsm_key_type_t key_type;
	//!< Indicates the type of the recipient public key.
	//!< Only HSM_KEY_TYPE_DSA_SM2_FP_256 is supported.
	hsm_op_sm2_eces_enc_flags_t flags;
	//!< bitmap specifying the operation attributes.
} op_sm2_eces_enc_args_t;

/**
 * Encrypt data usign SM2 ECES \n
 * User can call this function only after having opened a session.\n
 * SM2 ECES is supported with the requirements specified in the GB/T 32918.4. \n
 * The output (i.e. ciphertext) is stored in the format C= C1||C2||C3. Where,
 *      C1 = PC||x1||y1  where PC=04 and (x1,y1) are the coordinates of a an
 *                             elliptic curve point \n
 *      C2 = M xor t where t=KDF(x2||y2, input_size) and (x2,y2) are the
 *                             coordinates of a an elliptic curve point \n
 *      C3 = SM3 (x2||M||y2)

 *
 * \param session_hdl handle identifying the current session.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_sm2_eces_encryption(hsm_hdl_t session_hdl,
				  op_sm2_eces_enc_args_t *args);

/**
 *\addtogroup qxp_specific
 * \ref group19
 *
 * - \ref This API is not supported.
 *
 */
/**
 *\addtogroup dxl_specific
 * \ref group19
 *
 * - \ref The output_size should be a multiple of 4 bytes.
 *
 */
/** @} end of SM2 ECES encryption operation */
#endif
#endif
