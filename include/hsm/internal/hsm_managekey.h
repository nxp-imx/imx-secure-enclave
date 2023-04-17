// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#ifndef HSM_MANAGE_KEY_H
#define HSM_MANAGE_KEY_H

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "hsm_handle.h"
#include "hsm_utils.h"
#include "hsm_key.h"

/**
 *  @defgroup group3 Key management
 * @{
 */
typedef uint8_t hsm_op_manage_key_flags_t;

typedef struct {
	//!< pointer to the identifier of the key to be used for the operation.
	//   In case of create operation the new key identifier will be
	//   stored in this location.
	uint32_t *key_identifier;
	//!< identifier of the key to be used to decrypt the key to be
	//   imported (Key Encryption Key), only AES-256 key can be uses as KEK.
	//   It must be 0 if the HSM_OP_MANAGE_KEY_FLAGS_PART_UNIQUE_ROOT_KEK
	//   or HSM_OP_MANAGE_KEY_FLAGS_COMMON_ROOT_KEK flags are set.
	uint32_t kek_identifier;
	//!< length in bytes of the input key area. It must be eqaul to
	//   the length of the IV (12 bytes) + ciphertext + Tag (16 bytes).
	//   It must be 0 in case of delete operation.
	uint16_t input_size;
	//!< bitmap specifying the operation properties.
	hsm_op_manage_key_flags_t flags;
	//!< indicates the type of the key to be managed.
	hsm_key_type_t key_type;
	//!< key group of the imported key. It must be a value in
	//   the range 0-1023. Keys belonging to the same group can be cached in
	//   the HSM local memory through the hsm_manage_key_group API.
	hsm_key_group_t key_group;
	//!< bitmap specifying the properties of the key,
	//   in case of update operation it will replace the existing value.
	//   It must be 0 in case of delete operation.
	hsm_key_info_t key_info;
	//!< pointer to the input buffer. The input buffer is the concatenation
	//   of the IV, the encrypted key to be imported and the tag.
	//   It must be 0 in case of delete operation.
	uint8_t *input_data;
} op_manage_key_args_t;

/**
 * This command is designed to perform the following operations:
 *  - import a key creating a new key identifier (import and create)
 *  - import a key using an existing key identifier (import and update)
 *  - delete an existing key
 *
 * The key encryption key (KEK) can be previously pre-shared
 * or stored in the key store.
 *
 * The key to be imported must be encrypted by using the KEK as following:
 *  - Algorithm: AES GCM
 *  - Key: root KEK
 *  - AAD = 0
 *  - IV = 12 bytes. When encrypting with a given key,
 *  			the same IV MUST NOT be repeated.
 *  			Refer to SP 800-38D for recommendations.
 *  - Tag = 16 bytes
 *  - Plaintext: key to be imported
 *
 * The hsm_manage_key_ext function (described separately) allows
 * additional settings when importing keys.
 * When using the hsm_manage_key function to import a key,
 * all additional settings are set to their default values
 *
 * User can call this function only after having opened a
 * key management service flow
 *
 * \param key_management_hdl handle identifying the key management service flow.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_manage_key(hsm_hdl_t key_management_hdl,
			 op_manage_key_args_t *args);

//!< User can replace an existing key only by importing a key with
//   the same type of the original one.
#define HSM_OP_MANAGE_KEY_FLAGS_IMPORT_UPDATE \
			((hsm_op_manage_key_flags_t)(1u << 0))
//!< Import a key and create a new identifier.
#define HSM_OP_MANAGE_KEY_FLAGS_IMPORT_CREATE \
			((hsm_op_manage_key_flags_t)(1u << 1))
//!< Delete an existing key.
#define HSM_OP_MANAGE_KEY_FLAGS_DELETE \
			((hsm_op_manage_key_flags_t)(1u << 2))
//!< The key to be imported is encrypted using the part-unique root kek.
#define HSM_OP_MANAGE_KEY_FLAGS_PART_UNIQUE_ROOT_KEK \
			((hsm_op_manage_key_flags_t)(1u << 3))
//!< The key to be imported is encrypted using the common root kek.
#define HSM_OP_MANAGE_KEY_FLAGS_COMMON_ROOT_KEK \
			((hsm_op_manage_key_flags_t)(1u << 4))
//!< The request is completed only when the new key has been written in the NVM.
//   This is only applicable for persistent key.
#define HSM_OP_MANAGE_KEY_FLAGS_STRICT_OPERATION \
			((hsm_op_manage_key_flags_t)(1u << 7))

typedef uint8_t hsm_op_manage_key_ext_flags_t;
typedef struct {
	//!< pointer to the identifier of the key to be used for the operation.
	//   In case of create operation the new key identifier will be stored
	//   in this location.
	uint32_t *key_identifier;
	//!< identifier of the key to be used to decrypt the key to be imported
	//   (Key Encryption Key), only AES-256 key can be uses as KEK.
	//   It must be 0 if the HSM_OP_MANAGE_KEY_FLAGS_PART_UNIQUE_ROOT_KEK
	//   or HSM_OP_MANAGE_KEY_FLAGS_COMMON_ROOT_KEK flags are set.
	uint32_t kek_identifier;
	//!< length in bytes of the input key area. It must be eqaul to
	//   the length of the IV (12 bytes) + ciphertext + Tag (16 bytes).
	//   It must be 0 in case of delete operation.
	uint16_t input_size;
	//!< bitmap specifying the operation properties.
	hsm_op_manage_key_flags_t flags;
	//!< indicates the type of the key to be managed.
	hsm_key_type_t key_type;
	//!< key group of the imported key. It must be a value in
	//   the range 0-1023. Keys belonging to the same group can be cached in
	//   the HSM local memory through the hsm_manage_key_group API.
	hsm_key_group_t key_group;
	//!< bitmap specifying the properties of the key,
	//   in case of update operation it will replace the existing value.
	//   It must be 0 in case of delete operation.
	hsm_key_info_t key_info;
	//!< pointer to the input buffer. The input buffer is the concatenation
	//   of the IV, the encrypted key to be imported and the tag.
	//   It must be 0 in case of delete operation.
	uint8_t *input_data;
	//!< min mac length in bits to be set for this key, value 0 indicates
	//   use default (see op_mac_one_go_args_t for more details).
	//   Only accepted for keys that can be used for mac operations, must
	//   not be larger than maximum mac size that can be performed with the
	//   key. When in FIPS approved mode values < 32 bits are not allowed.
	uint8_t min_mac_len;
	//!< It must be 0.
	uint8_t reserved[3];
} op_manage_key_ext_args_t;


/**
 * Manage a key or a key pair with extended settings.
 * Basic operation is identical to hsm_manage_key,
 * but accepts additional settings.
 *
 * Currently the min_mac_len is the only additional setting accepted.
 *
 * \param key_management_hdl handle identifying the key management service flow.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_manage_key_ext(hsm_hdl_t key_management_hdl,
			     op_manage_key_ext_args_t *args);

/** @} end of key management service flow */
#endif
