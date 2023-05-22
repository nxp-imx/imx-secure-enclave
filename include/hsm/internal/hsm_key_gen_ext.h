// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#ifndef HSM_KEY_GEN_EXT_H
#define HSM_KEY_GEN_EXT_H

#include "internal/hsm_key.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_handle.h"
#include "internal/hsm_key_generate.h"

/**
 *  @defgroup group3 Key management
 * @{
 */

/**
 * structure defining
 */

#define FLAG 0

/**
 * Structure detailing the key generate operation member arguments
 */
typedef struct {
	uint32_t *key_identifier;
	//!< pointer to the identifier of the key to be used for the operation
	//!< In case of create operation the new key identifier will be stored
	//!< in this location
	uint16_t out_size;
	//!< length in bytes of the generated key
	//!< It must be 0 in case of symmetric keys
	hsm_op_key_gen_flags_t flags;
	//!< bitmap specifying the operation properties
	hsm_key_type_t key_type;
	//!< indicates which type of key must be generated
	hsm_key_group_t key_group;
	//!< Key group of the generated key. It must be a value in the range
	//!< 0-1023. Keys belonging to the same group can be cached in the HSM
	//!< local memory through the hsm_manage_key_group API
	hsm_key_info_t key_info;
	//!< bitmap specifying the properties of the key
	uint8_t *out_key;
	//!< pointer to the output area where the generated public key must be
	//!< written.
	uint8_t min_mac_len;
	//!< min mac length in bits to be set for this key, value 0 indicates
	//!< use default (see op_mac_one_go_args_t for more details).
	//!< Only accepted for keys that can be used for mac operations, must
	//!< not be larger than maximum mac size that can be performed with the
	//!< key. When in FIPS approved mode values < 32 bits are not allowed.
	uint8_t reserved[3];
	//!< It must be 0.
} op_generate_key_ext_args_t;

/**
 * Generate a key or a key pair with extended settings. Basic operation is
 * identical to hsm_generate_key, but accepts additional settings.
 * Currently the min_mac_len is the only additional setting accepted.
 *
 * \param key_management_hdl handle identifying the key management service flow.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_generate_key_ext(hsm_hdl_t key_management_hdl,
				op_generate_key_ext_args_t *args);

/** @} end of key management service flow */
#endif
