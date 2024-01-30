// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#ifndef HSM_BUT_H
#define HSM_BUT_H

#include "internal/hsm_common_def.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_handle.h"
#include "internal/hsm_key.h"
#ifndef PSA_COMPLIANT
/**
 *  @defgroup group Key Management
 * @{
 */

/**
 * Bit field describing the butterfly key expansion requested operation
 */
typedef uint8_t hsm_op_but_key_exp_flags_t;

/**
 * Structure describing the butterfly key expansion member arguments
 */
typedef struct {
	uint32_t key_identifier;
	//!< identifier of the key to be expanded.
	uint8_t *expansion_function_value;
	//!< pointer to the expansion function value input
	uint8_t *hash_value;
	//!< pointer to the hash value input.\n In case of explicit certificate,
	//!< the hash value address must be set to 0.
	uint8_t *pr_reconstruction_value;
	//!< pointer to the private reconstruction value input.
	//!< In case of explicit certificate, the pr_reconstruction_value address
	//!< must be set to 0.
	uint8_t expansion_function_value_size;
	//!< length in bytes of the expansion function input
	uint8_t hash_value_size;
	//!< length in bytes of the hash value input.
	//!< In case of explicit certificate, the hash_value_size parameter must
	//!< be set to 0.
	uint8_t pr_reconstruction_value_size;
	//!< length in bytes of the private reconstruction value input.
	//!< In case of explicit certificate, the pr_reconstruction_value_size
	//!< parameter must be set to 0.
	hsm_op_but_key_exp_flags_t flags;
	//!< bitmap specifying the operation properties
	uint32_t *dest_key_identifier;
	//!< pointer to identifier of the derived key to be used for the operation.
	//!< In case of create operation the new destination key identifier will be
	//!< stored in this location.
	uint8_t *output;
	//!< pointer to the output area where the public key must be written.
	uint16_t output_size;
	//!< length in bytes of the generated key, if the size is 0, no key is
	//!< copied in the output.
	hsm_key_type_t key_type;
	//!< indicates the type of the key to be derived.
	uint8_t reserved;
	hsm_key_group_t key_group;
	//!< it must be a value in the range 0-1023. Keys belonging to the same
	//!< group can be cached in the HSM local memory through the
	//!< hsm_manage_key_group API
	hsm_key_info_t key_info;
	//!< bitmap specifying the properties of the derived key.
} op_butt_key_exp_args_t;

/**
 * This command is designed to perform the butterfly key expansion operation on
 * an ECC private key in case of implicit and explicit certificates. Optionally
 * the resulting public key is exported.
 * The result of the key expansion function f_k is calculated outside the HSM
 * and passed as input. The expansion function is defined as f_k = f_k_int mod l,
 * where l is the order of the group of points on the curve.\n
 * User can call this function only after having opened a key management service flow.
 *
 * Explicit certificates:
 *  - f_k = expansion function value
 *
 * out_key = Key  + f_k
 * \n\n
 *
 * Implicit certificates:
 *  - f_k = expansion function value,
 *  - hash = hash value used in the derivation of the pseudonym ECC key,
 *  - pr_v = private reconstruction value
 *
 * out_key = (Key  + f_k)*hash + pr_v
 *
 * \param key_management_hdl handle identifying the key store management service flow.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_butterfly_key_expansion(hsm_hdl_t key_management_hdl,
				      op_butt_key_exp_args_t *args);

//!< User can replace an existing key only by generating a key with the same
//!< type of the original one.
#define HSM_OP_BUTTERFLY_KEY_FLAGS_UPDATE \
	((hsm_op_but_key_exp_flags_t)(1u << 0))

//!< Create a new key.
#define HSM_OP_BUTTERFLY_KEY_FLAGS_CREATE \
	((hsm_op_but_key_exp_flags_t)(1u << 1))

//!< butterfly key expansion using implicit certificate.
#define HSM_OP_BUTTERFLY_KEY_FLAGS_IMPLICIT_CERTIF \
	((hsm_op_but_key_exp_flags_t)(0u << 2))

//!< butterfly key expansion using explicit certificate.
#define HSM_OP_BUTTERFLY_KEY_FLAGS_EXPLICIT_CERTIF \
	((hsm_op_but_key_exp_flags_t)(1u << 2))

//!< The request is completed only when the new key has been written in the NVM.
#define HSM_OP_BUTTERFLY_KEY_FLAGS_STRICT_OPERATION \
	((hsm_op_but_key_exp_flags_t)(1u << 7))

/**
 *\addtogroup qxp_specific
 * \ref group3
 *
 * - \ref HSM_OP_MANAGE_KEY_GROUP_FLAGS_DELETE is not supported.
 *
 * - \ref HSM_KEY_TYPE_ECDSA_NIST_P521 is not supported.
 * - \ref HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_320 is not supported.
 * - \ref HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_512 is not supported.
 * - \ref HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_256 is not supported.
 * - \ref HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_320 is not supported.
 * - \ref HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_384 is not supported.
 * - \ref HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_512 is not supported.
 * - \ref HSM_KEY_TYPE_DSA_SM2_FP_256 is not supported.
 * - \ref HSM_KEY_TYPE_SM4_128 is not supported.
 * - \ref HSM_KEY_TYPE_HMAC_224 is not supported.
 * - \ref HSM_KEY_TYPE_HMAC_256 is not supported.
 * - \ref HSM_KEY_TYPE_HMAC_384 is not supported.
 * - \ref HSM_KEY_TYPE_HMAC_512 is not supported.
 *
 * - \ref hsm_butterfly_key_expansion: This feature is disabled when part is
 *        running in FIPS approved mode. Any call to this API will results in a
 *        HSM_FEATURE_DISABLED error.
 * - \ref hsm_key_type_t of op_butt_key_exp_args_t: Only following are supported:
 *        HSM_KEY_TYPE_ECDSA_NIST_P256, and
 *        HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_256
 */

/**
 *\addtogroup dxl_specific
 * \ref group3
 *
 * - \ref HSM_OP_MANAGE_KEY_GROUP_FLAGS_DELETE is not supported.
 *
 * - \ref HSM_KEY_TYPE_HMAC_224 is not supported.
 * - \ref HSM_KEY_TYPE_HMAC_256 is not supported.
 * - \ref HSM_KEY_TYPE_HMAC_384 is not supported.
 * - \ref HSM_KEY_TYPE_HMAC_512 is not supported.
 *
 * - \ref hsm_key_type_t of op_butt_key_exp_args_t: Only following are supported:
 *   HSM_KEY_TYPE_ECDSA_NIST_P256,
 *   HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_256 and
 *   HSM_KEY_TYPE_DSA_SM2_FP_256 are supported.
 *
 */
/** @} end of key management service flow */
#endif
#endif
