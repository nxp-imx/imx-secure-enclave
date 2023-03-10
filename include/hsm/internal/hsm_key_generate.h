/*
 * Copyright 2022-2023 NXP
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

#ifndef HSM_KEY_GENERATE_H
#define HSM_KEY_GENERATE_H

#include "internal/hsm_key.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_handle.h"

typedef uint8_t hsm_op_key_gen_flags_t;

#ifdef PSA_COMPLIANT
//!< Reserverd Bits 0 - 6
#else
/* Flags for NON-PSA COMPLIANT platforms such as SECO.
 */
//!< User can replace an existing key only by generating a key with
//   the same type of the original one.
#define HSM_OP_KEY_GENERATION_FLAGS_UPDATE \
		((hsm_op_key_gen_flags_t)(1u << 0))

//!< Create a new key.
#define HSM_OP_KEY_GENERATION_FLAGS_CREATE \
		((hsm_op_key_gen_flags_t)(1u << 1))
#endif /* PSA_COMPLIANT */

//!< The request is completed only when the new key has been written in the NVM.
//   This applicable for persistent key only.
#define HSM_OP_KEY_GENERATION_FLAGS_STRICT_OPERATION \
			((hsm_op_key_gen_flags_t)(1u << 7))

typedef struct {
	//!< pointer to the identifier of the key to be used for the operation.
	//   In case of create operation the new key identifier will be stored
	//   in this location.
	uint32_t *key_identifier;
	//!< length in bytes of the generated key.
	//   It must be 0 in case of symmetric keys.
	uint16_t out_size;
	//!< bitmap specifying the operation properties.
	hsm_op_key_gen_flags_t flags;
	//!< indicates which type of key must be generated.
	hsm_key_type_t key_type;
	//!< Key group of the generated key.
	//   It must be a value in the range 0-1023.
	//   Keys belonging to the same group can be cached in the HSM local
	//   memory through the hsm_manage_key_group API.
	hsm_key_group_t key_group;
	//!< pointer to the output area where the generated public key
	//   must be written.
	uint8_t *out_key;
#ifdef PSA_COMPLIANT
	hsm_bit_key_sz_t bit_key_sz;
	//!< defines the device lifecycle in which the key is usable.
	//	 If it is set to 0, current device lifecycle is used.
	hsm_key_lifecycle_t key_lifecycle;
	hsm_key_lifetime_t key_lifetime;
	hsm_key_usage_t key_usage;
	hsm_permitted_algo_t permitted_algo;
#else
	//!< bitmap specifying the properties of the key.
	hsm_key_info_t key_info;
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
#endif
