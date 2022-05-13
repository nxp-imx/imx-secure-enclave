/*
 * Copyright 2022 NXP
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

#ifndef HSM_SIGN_GEN_H
#define HSM_SIGN_GEN_H

#include <stdint.h>

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"

/**
 *  @defgroup group5 Signature generation
 * @{
 */
typedef uint8_t hsm_svc_signature_generation_flags_t;
typedef struct {
	hsm_hdl_t signature_gen_hdl;
	//!< bitmap specifying the services properties.
	hsm_svc_signature_generation_flags_t flags;
	uint8_t reserved[3];
} open_svc_sign_gen_args_t;

/**
 * Open a signature generation service flow\n
 * User can call this function only after having opened
 * a key store service flow.
 *
 * User must open this service in order to perform
 * signature generation operations.
 *
 * \param key_store_hdl: handle identifying the key store service flow.
 * \param args: pointer to the structure containing the function arguments.
 * \param signature_gen_hdl: pointer to where the signature generation
 *                           service flow handle must be written.
 *
 * \return error code
 */
hsm_err_t hsm_open_signature_generation_service(hsm_hdl_t key_store_hdl,
						open_svc_sign_gen_args_t *args,
						hsm_hdl_t *signature_gen_hdl);

/**
 * Terminate a previously opened signature generation service flow
 *
 * \param signature_gen_hdl: handle identifying the signature generation
 *                           service flow to be closed.
 *
 * \return error code
 */
hsm_err_t hsm_close_signature_generation_service(hsm_hdl_t signature_gen_hdl);

typedef uint8_t hsm_op_generate_sign_flags_t;

//! Bit field indicating the requested operations:
//! Bit 0:
//!  - 0: Input is the message digest.
//!  - 1: Input is the actual message.
#define HSM_OP_GENERATE_SIGN_FLAGS_INPUT_DIGEST \
				((hsm_op_generate_sign_flags_t)(0u << 0))
#define HSM_OP_GENERATE_SIGN_FLAGS_INPUT_MESSAGE \
				((hsm_op_generate_sign_flags_t)(1u << 0))

#ifdef CONFIG_COMPRESSED_ECC_POINT
//! Bit field indicating the non-PSA compliant requested operations:
//! Bit 1:
#define HSM_OP_GENERATE_SIGN_FLAGS_COMPRESSED_POINT \
				((hsm_op_generate_sign_flags_t)(1u << 1))
#endif

#ifdef PSA_COMPLIANT
//! Bit field indicating the PSA compliant requested operations:
//! Bit 2 to 7: Reserved.

typedef enum {
	HSM_SIGNATURE_SCHEME_RSA_PKCS1_V15_SHA1		= 0x06000205,
	HSM_SIGNATURE_SCHEME_RSA_PKCS1_V15_SHA224       = 0x06000208,
	HSM_SIGNATURE_SCHEME_RSA_PKCS1_V15_SHA256       = 0x06000209,
	HSM_SIGNATURE_SCHEME_RSA_PKCS1_V15_SHA384       = 0x0600020A,
	HSM_SIGNATURE_SCHEME_RSA_PKCS1_V15_SHA512       = 0x0600020B,
	HSM_SIGNATURE_SCHEME_RSA_PKCS1_PSS_MGF1_SHA1    = 0x06000305,
	HSM_SIGNATURE_SCHEME_RSA_PKCS1_PSS_MGF1_SHA224  = 0x06000308,
	HSM_SIGNATURE_SCHEME_RSA_PKCS1_PSS_MGF1_SHA256  = 0x06000309,
	HSM_SIGNATURE_SCHEME_RSA_PKCS1_PSS_MGF1_SHA384  = 0x0600030A,
	HSM_SIGNATURE_SCHEME_RSA_PKCS1_PSS_MGF1_SHA512  = 0x0600030B,
	HSM_SIGNATURE_SCHEME_ECDSA_SHA1_NIST_ECC        = 0x06000605,
	HSM_SIGNATURE_SCHEME_ECDSA_SHA224               = 0x06000608,
	HSM_SIGNATURE_SCHEME_ECDSA_SHA256               = 0x06000609,
	HSM_SIGNATURE_SCHEME_ECDSA_SHA384               = 0x0600060A,
	HSM_SIGNATURE_SCHEME_ECDSA_SHA512               = 0x0600060B,
} hsm_signature_scheme_id_t;

#else

//! Bit 2: HSM finalizes the signature by using the artifacts of the previously
//!        executed hsm_prepare_signature API. The API fails if no artifacts
//!        related to the requested scheme id are available.
#define HSM_OP_GENERATE_SIGN_FLAGS_LOW_LATENCY_SIGNATURE \
				((hsm_op_generate_sign_flags_t)(1u << 2))

//! Bit 3 to 7: Reserved.

typedef uint8_t hsm_signature_scheme_id_t;
#define HSM_SIGNATURE_SCHEME_ECDSA_NIST_P256_SHA_256 \
					((hsm_signature_scheme_id_t)0x02u)
#define HSM_SIGNATURE_SCHEME_ECDSA_NIST_P384_SHA_384 \
					((hsm_signature_scheme_id_t)0x03u)
#define HSM_SIGNATURE_SCHEME_ECDSA_NIST_P521_SHA_512 \
					((hsm_signature_scheme_id_t)0x04u)
#define HSM_SIGNATURE_SCHEME_ECDSA_BRAINPOOL_R1_256_SHA_256 \
					((hsm_signature_scheme_id_t)0x13u)
#define HSM_SIGNATURE_SCHEME_ECDSA_BRAINPOOL_R1_320_SHA_384 \
					((hsm_signature_scheme_id_t)0x14u)
#define HSM_SIGNATURE_SCHEME_ECDSA_BRAINPOOL_R1_384_SHA_384 \
					((hsm_signature_scheme_id_t)0x15u)
#define HSM_SIGNATURE_SCHEME_ECDSA_BRAINPOOL_R1_512_SHA_512 \
					((hsm_signature_scheme_id_t)0x16u)
#define HSM_SIGNATURE_SCHEME_ECDSA_BRAINPOOL_T1_256_SHA_256 \
					((hsm_signature_scheme_id_t)0x23u)
#define HSM_SIGNATURE_SCHEME_ECDSA_BRAINPOOL_T1_320_SHA_384 \
					((hsm_signature_scheme_id_t)0x24u)
#define HSM_SIGNATURE_SCHEME_ECDSA_BRAINPOOL_T1_384_SHA_384 \
					((hsm_signature_scheme_id_t)0x25u)
#define HSM_SIGNATURE_SCHEME_ECDSA_BRAINPOOL_T1_512_SHA_512 \
					((hsm_signature_scheme_id_t)0x26u)
#define HSM_SIGNATURE_SCHEME_DSA_SM2_FP_256_SM3 \
					((hsm_signature_scheme_id_t)0x43u)

#endif

typedef struct {
	//!< identifier of the key to be used for the operation
	uint32_t key_identifier;
	//!< pointer to the input (message or message digest) to be signed
	uint8_t *message;
	//!< pointer to the output area where the signature must be stored.
	//   The signature S=(r,s) is stored in format r||s||Ry where:
	//   - Ry is an additional byte containing the lsb of y.
	//     Ry has to be considered valid only if
	//     the HSM_OP_GENERATE_SIGN_FLAGS_COMPRESSED_POINT is set.
	uint8_t *signature;
	//!< length in bytes of the output
	uint16_t signature_size;
	//!< length in bytes of the input
	uint32_t message_size;
	//!< identifier of the digital signature scheme to be used
	//   for the operation
	hsm_signature_scheme_id_t scheme_id;
	//!< bitmap specifying the operation attributes
	hsm_op_generate_sign_flags_t flags;
#ifdef PSA_COMPLIANT
	uint8_t reserved[3];
#else
	uint8_t reserved[2];
#endif
} op_generate_sign_args_t;

/**
 * Generate a digital signature according to the signature scheme
 * User can call this function only after having opened a signature
 * generation service flow.
 *
 * The signature S=(r,s) is stored in the format r||s||Ry where:
 * - Ry is an additional byte containing the lsb of y.
 *   Ry has to be considered valid only
 *   if the HSM_OP_GENERATE_SIGN_FLAGS_COMPRESSED_POINT is set.
 *
 * In case of HSM_SIGNATURE_SCHEME_DSA_SM2_FP_256_SM3, message of
 * op_generate_sign_args_t should be (as specified in GB/T 32918):
 *       - equal to Z||M in case of HSM_OP_GENERATE_SIGN_FLAGS_INPUT_MESSAGE
 *       - equal to SM3(Z||M) in case of HSM_OP_GENERATE_SIGN_FLAGS_INPUT_DIGEST
 *
 * \param signature_gen_hdl: handle identifying the signature generation
 *                           service flow.
 * \param args: pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_generate_signature(hsm_hdl_t signature_gen_hdl,
				 op_generate_sign_args_t *args);

typedef uint8_t hsm_op_prepare_signature_flags_t;
typedef struct {
	//!< identifier of the digital signature scheme to be used
	//   for the operation.
	hsm_signature_scheme_id_t scheme_id;
	//!< bitmap specifying the operation attributes
	hsm_op_prepare_signature_flags_t flags;
	uint16_t reserved;
} op_prepare_sign_args_t;

/**
 * Prepare the creation of a signature by pre-calculating the operations having
 * not dependencies on the input message.
 *
 * The pre-calculated value will be stored internally and
 * used once call hsm_generate_signature. Up to 20 pre-calculated values
 * can be stored, additional preparation operations will have no effects.
 *
 * User can call this function only after having opened a
 * signature generation service flow.
 *
 * The signature S=(r,s) is stored in the format r||s||Ry where:
 * - Ry is an additional byte containing the lsb of y,
 *   Ry has to be considered valid only
 *   if the HSM_OP_PREPARE_SIGN_COMPRESSED_POINT is set.
 *
 * \param signature_gen_hdl: handle identifying the signature generation
 *                           service flow
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_prepare_signature(hsm_hdl_t signature_gen_hdl,
				op_prepare_sign_args_t *args);
#define HSM_OP_PREPARE_SIGN_INPUT_DIGEST \
				((hsm_op_prepare_signature_flags_t)(0u << 0))
#define HSM_OP_PREPARE_SIGN_INPUT_MESSAGE \
				((hsm_op_prepare_signature_flags_t)(1u << 0))
#define HSM_OP_PREPARE_SIGN_COMPRESSED_POINT \
				((hsm_op_prepare_signature_flags_t)(1u << 1))

/**
 *\addtogroup qxp_specific
 * \ref group5
 *
 * - \ref HSM_SIGNATURE_SCHEME_ECDSA_NIST_P521_SHA_512 is not supported.
 * - \ref HSM_SIGNATURE_SCHEME_ECDSA_BRAINPOOL_R1_320_SHA_384 is not supported.
 * - \ref HSM_SIGNATURE_SCHEME_ECDSA_BRAINPOOL_R1_512_SHA_512 is not supported.
 * - \ref HSM_SIGNATURE_SCHEME_ECDSA_BRAINPOOL_T1_256_SHA_256 is not supported.
 * - \ref HSM_SIGNATURE_SCHEME_ECDSA_BRAINPOOL_T1_320_SHA_384 is not supported.
 * - \ref HSM_SIGNATURE_SCHEME_ECDSA_BRAINPOOL_T1_384_SHA_384 is not supported.
 * - \ref HSM_SIGNATURE_SCHEME_ECDSA_BRAINPOOL_T1_512_SHA_512 is not supported.
 * - \ref HSM_SIGNATURE_SCHEME_DSA_SM2_FP_256_SM3 is not supported.
 *
 */

/**
 *\addtogroup dxl_specific
 * \ref group5
 *
 * - \ref HSM_OP_GENERATE_SIGN_FLAGS_COMPRESSED_POINT is not supported,
 *        in case of HSM_SIGNATURE_SCHEME_DSA_SM2_FP_256_SM3.
 *
 */
/** @} end of signature generation service flow */
#endif
