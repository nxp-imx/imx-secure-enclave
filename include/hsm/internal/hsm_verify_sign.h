// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#ifndef HSM_VERIFY_SIGN_H
#define HSM_VERIFY_SIGN_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "internal/hsm_sign_gen.h"
#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_key.h"

/**
 *  @defgroup group6 Signature verification
 * @{
 */
#ifndef PSA_COMPLIANT
typedef uint8_t hsm_svc_signature_verification_flags_t;
#endif
/**
 *  Structure to represent verify sign open service arguments
 */
typedef struct {
#ifndef PSA_COMPLIANT
	//!< bitmap indicating the service flow properties
	hsm_svc_signature_verification_flags_t flags;
#endif
	hsm_hdl_t sig_ver_hdl;
} open_svc_sign_ver_args_t;

/**
 *  Bit indicating the response verification status
 */
typedef uint32_t hsm_verification_status_t;
/**
 * Bit indicating the requested operations
 */
typedef uint8_t hsm_op_verify_sign_flags_t;
/**
 *  Structure to represent verify signature operation arguments
 */
typedef struct {
	uint8_t *key;
	//!< pointer to the public key to be used for the verification.
	//!< If the HSM_OP_VERIFY_SIGN_FLAGS_KEY_INTERNAL is set, it must point
	//!< to the key reference returned by the hsm_import_public_key API.
	uint8_t *message;
	//!< pointer to the input (message or message digest)
	uint8_t *signature;
	//!< pointer to the input signature. The signature S=(r,s) is expected
	//!< to be in the format r||s||Ry where Ry is an additional byte
	//!< containing the lsb of y. Ry will be considered as valid only if
	//!< the HSM_OP_VERIFY_SIGN_FLAGS_COMPRESSED_POINT is set.
	uint16_t key_size;
	//!< length in bytes of the input key
	uint16_t signature_size;
	//!< length in bytes of the output - it must contain one additional
	//!< byte where to store the Ry.
	uint32_t message_size;
	//!< length in bytes of the input message.
	hsm_verification_status_t verification_status;
	//!< verification status.
	hsm_signature_scheme_id_t scheme_id;
	//!< identifier of the digital signature scheme to be used
	//!< for the operation
#ifdef PSA_COMPLIANT
	uint16_t salt_len;
	//!< salt length in bytes
	hsm_bit_key_sz_t key_sz;
	//!< indicates key security size in bits.
	hsm_pubkey_type_t pkey_type;
	//!< indicates the public key type
#endif
	hsm_op_verify_sign_flags_t flags;
	//!< bitmap specifying the operation attributes
#ifndef PSA_COMPLIANT
	hsm_svc_signature_verification_flags_t svc_flags;
	//!< bitmap specifying the svc flow attributes
#endif
} op_verify_sign_args_t;

/**
 * User must open this service in order to perform signature verification
 * operations.
 * User can call this function only after having opened a session.
 *
 * \param session_hdl handle identifying the current session.
 * \param args pointer to the structure containing the function arguments.
 * \param signature_ver_hdl pointer to where the signature verification service
 *                          flow handle must be written.
 *
 * \return error code
 */
hsm_err_t hsm_open_signature_verification_service(hsm_hdl_t session_hdl,
						open_svc_sign_ver_args_t *args,
						hsm_hdl_t *signature_ver_hdl);


/**
 * Terminate a previously opened signature verification service flow
 *
 * \param signature_ver_hdl handle identifying the signature verification service flow to be closed.
 *
 * \return error code
 */
hsm_err_t hsm_close_signature_verification_service(hsm_hdl_t signature_ver_hdl);

/**
 * Verify a digital signature according to the signature scheme
 * User can call this function only after having opened a signature
 * verification service flow.
 *
 * The signature S=(r,s) is expected to be in format r||s||Ry where:
 * - Ry is an additional byte containing the lsb of y.
 *   Ry will be considered as valid only,
 *   if the HSM_OP_VERIFY_SIGN_FLAGS_COMPRESSED_POINT is set.
 *
 * Only not-compressed keys (x,y) can be used by this command.
 * Compressed keys can be decompressed by using the dedicated API.
 *
 * In case of HSM_SIGNATURE_SCHEME_DSA_SM2_FP_256_SM3, message of
 * op_verify_sign_args_t should be (as specified in GB/T 32918):
 *      - equal to Z||M in case of HSM_OP_VERIFY_SIGN_FLAGS_INPUT_MESSAGE \n
 *      - equal to SM3(Z||M) in case of HSM_OP_VERIFY_SIGN_FLAGS_INPUT_DIGEST
 *
 * \param signature_ver_hdl: handle identifying the signature
 *                           verification service flow.
 * \param args: pointer to the structure containing the function arguments.
 * \param status: pointer to where the verification status must be stored
 *                if the verification succeed the value
 *                HSM_VERIFICATION_STATUS_SUCCESS is returned.
 *
 * \return error code
 */
hsm_err_t hsm_verify_signature(hsm_hdl_t signature_ver_hdl,
			       op_verify_sign_args_t *args,
			       hsm_verification_status_t *status);
/**
 *  Verify signature bit indicating input is message digest
 */
#define HSM_OP_VERIFY_SIGN_FLAGS_INPUT_DIGEST \
				((hsm_op_verify_sign_flags_t)(0u << 0))

/**
 *  Verify signature bit indicating input is actual message
 */
#define HSM_OP_VERIFY_SIGN_FLAGS_INPUT_MESSAGE \
				((hsm_op_verify_sign_flags_t)(1u << 0))

/**
 *  Verify signature bit indicating input based on signature format
 */
#define HSM_OP_VERIFY_SIGN_FLAGS_COMPRESSED_POINT \
				((hsm_op_verify_sign_flags_t)(1u << 1))

/**
 *  Verify signature bit indicating input is key argument
 */
#define HSM_OP_VERIFY_SIGN_FLAGS_KEY_INTERNAL \
				((hsm_op_verify_sign_flags_t)(1u << 2))

/**
 *  Verify signature response success status
 */
#define HSM_VERIFICATION_STATUS_SUCCESS \
				((hsm_verification_status_t)(0x5A3CC3A5u))
/**
 *  Verify signature response failure status
 */
#define HSM_VERIFICATION_STATUS_FAILURE \
				((hsm_verification_status_t)(0x2B4DD4B2u))

/** @} end of signature verification service flow */
#endif
