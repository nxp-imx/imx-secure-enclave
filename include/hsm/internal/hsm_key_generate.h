// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2024, 2026 NXP
 */

#ifndef HSM_KEY_GENERATE_H
#define HSM_KEY_GENERATE_H

#include "hsm_key.h"
#include "hsm_utils.h"
#include "hsm_handle.h"

/**
 *  @defgroup group3 Key management
 * @{
 */

/**
 * Bitmap specifying the key generate operation supported properties.
 */
typedef uint8_t hsm_op_key_gen_flags_t;

#ifdef PSA_COMPLIANT
#define HSM_OP_KEY_GENERATION_FLAGS_PLAINTEXT_KEY \
			((hsm_op_key_gen_flags_t)(1u << 3))
//!< Plaintext key. Key is generated and exported to user’s memory.

#define HSM_OP_KEY_GENERATION_FLAGS_MONOTONIC_COUNTER \
			((hsm_op_key_gen_flags_t)(1u << 5))
//!< Monotonic counter increment when used in conjunction with SYNC,
//!< the request is completed only when the monotonic counter has been updated.
#else
/* Flags for NON-PSA COMPLIANT platforms such as SECO.
 */
#define HSM_OP_KEY_GENERATION_FLAGS_UPDATE \
		((hsm_op_key_gen_flags_t)(1u << 0))
//!< User can replace an existing key only by generating a key with
//!< the same type of the original one.

#define HSM_OP_KEY_GENERATION_FLAGS_CREATE \
		((hsm_op_key_gen_flags_t)(1u << 1))
//!< Create a new key.
#endif /* PSA_COMPLIANT */

#define HSM_OP_KEY_GENERATION_FLAGS_STRICT_OPERATION \
			((hsm_op_key_gen_flags_t)(1u << 7))
//!< The request is completed only when the new key has been written in the NVM.
//!< This applicable for persistent key only.

/**
 * Structure describing the generate key operation member arguments
 */
typedef struct {
	uint32_t *key_identifier;
	//!< pointer to the identifier of the key to be used for the operation.
	//!< In case of create operation the new key identifier will be stored
	//!< in this location.
#ifdef PSA_COMPLIANT
	//!< In case of using key identifier (i.e. opaque key),
	//!< it must be ensured that the flag for PLAINTEXT key is not set.
#endif
	uint16_t out_size;
	//!< length in bytes of the generated public key.
	//!< It must be 0 in case of symmetric keys.
	hsm_op_key_gen_flags_t flags;
	//!< bitmap specifying the operation properties.
	hsm_key_type_t key_type;
	//!< indicates which type of key must be generated.
	hsm_key_group_t key_group;
	//!< Key group of the generated key.
#ifdef PSA_COMPLIANT
	//!< It must be a value in the range 0-99.
	//!< Reserved in case of PLAINTEXT flag usage.
#else
	//!< It must be a value in the range 0-1023.
#endif
	//!< Keys belonging to the same group can be cached in the HSM local
	//!< memory through the hsm_manage_key_group API.
	uint8_t *out_key;
	//!< pointer to the output area where the generated public key
	//!< must be written.
#ifdef PSA_COMPLIANT
	uint16_t exp_out_size;
	//!< expected public key output buffer size, valid in case of HSM_OUT_TOO_SMALL
	//!< (0x1D) error code
	hsm_bit_key_sz_t bit_key_sz;
	//!< indicates key security size in bits.
	hsm_key_lifecycle_t key_lifecycle;
	//!< defines the key lifecycle in which the key is usable.
	//!< If it is set to 0, current key lifecycle is used.
	//!< Reserved in case of PLAINTEXT flag usage.
	hsm_key_lifetime_t key_lifetime;
	//!< this attribute comprises of two indicaters-key persistence level
	//!< and location where the key is stored.
	//!< Reserved in case of PLAINTEXT flag usage.
	hsm_key_usage_t key_usage;
	//!< indicates the cryptographic operations that key can execute.
	//!< Reserved in case of PLAINTEXT flag usage.
	hsm_permitted_algo_t permitted_algo;
	//!< indicates the key permitted algorithm.
	//!< Reserved in case of PLAINTEXT flag usage.
	uint16_t priv_out_key_sz;
	//!< length in bytes of the generated private key.
	//!< Only valid with PLAINTEXT flag.
	uint8_t *priv_out_key;
	//!< pointer to the output area where the generated private key,
	//!< must be written.
	//!< Only valid with PLAINTEXT flag.
	uint16_t exp_priv_out_key_sz;
	//!< expected private key output buffer size, valid in case of HSM_OUT_TOO_SMALL
	//!< (0x1D) error code.
	//!< Only valid with PLAINTEXT flag.
#else
	hsm_key_info_t key_info;
	//!< bitmap specifying the properties of the key.
#endif
} op_generate_key_args_t;

/**
 * Generate a key or a key pair. Only the confidential keys
 * (symmetric and private keys) are stored in the internal key store, while
 * the non-confidential keys (public key) are exported.
 *
 * The generated key can be stored using a new or existing key identifier with
 * the restriction that an existing key can be replaced only by a key of the
 * same type.
 *
 * \param key_management_hdl handle identifying the key management service flow.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_generate_key(hsm_hdl_t key_management_hdl,
			   op_generate_key_args_t *args);
/** @} end of key management service flow */
#endif
