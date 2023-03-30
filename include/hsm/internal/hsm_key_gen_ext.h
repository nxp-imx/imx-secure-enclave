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
	//!< Key group of the generated key. It must be a value in the range
	//   0-1023. Keys belonging to the same group can be cached in the HSM
	//   local memory through the hsm_manage_key_group API.
	hsm_key_group_t key_group;
	//!< bitmap specifying the properties of the key.
	hsm_key_info_t key_info;
	//!< pointer to the output area where the generated public key must be
	//   written.
	uint8_t *out_key;
	//!< min mac length in bits to be set for this key, value 0 indicates
	//   use default (see op_mac_one_go_args_t for more details).
	//   Only accepted for keys that can be used for mac operations, must
	//   not be larger than maximum mac size that can be performed with the
	//   key. When in FIPS approved mode values < 32 bits are not allowed.
	uint8_t min_mac_len;
	//!< It must be 0.
	uint8_t reserved[3];
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
