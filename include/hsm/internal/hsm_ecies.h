// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef HSM_ECIES_H
#define HSM_ECIES_H

#include "internal/hsm_common_def.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_handle.h"
#include "internal/hsm_key.h"

/**
 *  @defgroup group11 ECIES encryption
 * @{
 */

/**
 * Bitmap specifying the ecies encryption operation supported properties
 */
typedef uint8_t hsm_op_ecies_enc_flags_t;

/**
 * Structure specifying the  ecies encryption operation member arguments
 */
typedef struct {
	uint8_t *input;
	//!< pointer to the input plaintext
	uint8_t *pub_key;
	//!< pointer to the input recipient public key
	uint8_t *p1;
	//!< pointer to the KDF P1 input parameter
	uint8_t *p2;
	//!< pointer to the MAC P2 input parameter should be NULL
	uint8_t *output;
	//!< pointer to the output area where the VCT must be written
	uint32_t input_size;
	//!< length in bytes of the input plaintext should be equal to 16 bytes
	uint16_t p1_size;
	//!< length in bytes of the KDF P1 parameter should be equal to 32 bytes
	uint16_t p2_size;
	//!< length in bytes of the MAC P2 parameter should be zero reserved for
	//!<  generic use cases
	uint16_t pub_key_size;
	//!< length in bytes of the recipient public key should be equal to 64 bytes
	uint16_t mac_size;
	//!< length in bytes of the requested message authentication code should
	//!<  be equal to 16 bytes
	uint32_t out_size;
	//!< length in bytes of the output VCT should be equal to 96 bytes
	hsm_key_type_t key_type;
	//!< indicates the type of the recipient public key
	hsm_op_ecies_enc_flags_t flags;
	//!< bitmap specifying the operation attributes.
} op_ecies_enc_args_t;

/**
 * Encrypt data usign ECIES \n
 * User can call this function only after having opened a session.\n
 * ECIES is supported with the constraints specified in 1609.2-2016.
 *
 * \param session_hdl handle identifying the current session.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_ecies_encryption(hsm_hdl_t session_hdl, op_ecies_enc_args_t *args);

/**
 * Bitmap specifying the ecies decryption operation supported properties
 */
typedef uint8_t hsm_op_ecies_dec_flags_t;

/**
 * Structure specifying the ecies decryption operation member arguments
 */
typedef struct {
	uint32_t key_identifier;
	//!< identifier of the private key to be used for the operation
	uint8_t *input;
	//!< pointer to the VCT input
	uint8_t *p1;
	//!< pointer to the KDF P1 input parameter
	uint8_t *p2;
	//!< pointer to the MAC P2 input parameter should be NULL
	uint8_t *output;
	//!< pointer to the output area where the plaintext must be written
	uint32_t input_size;
	//!< length in bytes of the input VCT should be equal to 96 bytes
	uint32_t output_size;
	//!< length in bytes of the output plaintext should be equal to 16 bytes
	uint16_t p1_size;
	//!< length in bytes of the KDF P1 parameter should be equal to 32 bytes
	uint16_t p2_size;
	//!< length in bytes of the MAC P2 parameter should be zero reserved for
	//!<  generic use cases
	uint16_t mac_size;
	//!< length in bytes of the requested message authentication code should
	//!<  be equal to 16 bytes
	hsm_key_type_t key_type;
	//!< indicates the type of the used key
	hsm_op_ecies_dec_flags_t flags;
	//!< bitmap specifying the operation attributes.
} op_ecies_dec_args_t;

/**
 * Decrypt data usign ECIES \n
 * User can call this function only after having opened a cipher  store service flow.\n
 * ECIES is supported with the constraints specified in 1609.2-2016.
 *
 * \param session_hdl handle identifying the current session.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_ecies_decryption(hsm_hdl_t cipher_hdl, op_ecies_dec_args_t *args);

/**
 *\addtogroup qxp_specific
 * \ref group11
 *
 * - \ref hsm_ecies_encryption: This feature is disabled when part is running in
 *        FIPS approved mode. Any call to this API will results in a
 *        HSM_FEATURE_DISABLED error.
 * - \ref hsm_key_type_t of op_ecies_enc_args_t: Only followinga are supported:
 *        HSM_KEY_TYPE_ECDSA_NIST_P256, and
 *        HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_256.
 *
 */

/**
 *\addtogroup dxl_specific
 * \ref group11
 *
 * - \ref hsm_key_type_t of op_ecies_enc_args_t: Only following are supported:
 *        HSM_KEY_TYPE_ECDSA_NIST_P256, and
 *        HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_256.
 *
 */
/** @} end of ECIES encryption operation */
#endif
