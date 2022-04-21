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

#ifndef HSM_IMPORT_KEY_H
#define HSM_IMPORT_KEY_H

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_key.h"

#define HSM_IMPORT_IV_LEN	12
#define HSM_IMPORT_TAG_LEN	16

typedef uint8_t hsm_op_import_key_flags_t;

//!< Bit 0: AES 256 bits GCM algorithm (not supported by S400).
#define HSM_OP_IMPORT_KEY_FLAGS_ALGO_AES256_GCM \
	((hsm_op_import_key_flags_t)(1u << 0))
//!< Bit 1: AES 256 bits CCM algorithm.
#define HSM_OP_IMPORT_KEY_FLAGS_ALGO_AES256_CCM \
	((hsm_op_import_key_flags_t)(1u << 1))
//!< Bit 2: Reserved.
//!< Bit 3: The key to be imported is encrypted using the part-unique root KEK.
#define HSM_OP_IMPORT_KEY_FLAGS_PART_UNIQUE_ROOT_KEK \
	((hsm_op_import_key_flags_t)(1u << 3))
//!< Bit 4: The key to be imported is encrypted using the common root KEK.
#define HSM_OP_IMPORT_KEY_FLAGS_COMMON_ROOT_KEK \
	((hsm_op_import_key_flags_t)(1u << 4))
//!< Bit 5: The key to be imported is wrapped with provisioned wrap key.
#define HSM_OP_IMPORT_KEY_FLAGS_WRP_PRV_WRPK \
	((hsm_op_import_key_flags_t)(1u << 5))
//!< Bit 6: Reserved.
//!< Bit 7: Strict: Request completed - New key written to NVM with updated MC.
#define HSM_OP_IMPORT_KEY_FLAGS_STRICT_OPERATION \
	((hsm_op_import_key_flags_t)(1u << 7))

typedef struct {
	//!< Identifier of the KEK used to encrypt the key to be imported
	//   (Ignored if KEK is not used as set as part of "flags" field).
	uint32_t *key_identifier;
	//!< Size in bytes of the encrypted or wrapped key to be retrieved at
	//   the private key input address stored in "uint8_t *key".
	uint16_t encryted_prv_key_sz;
	//!< - Key group of the imported key. It must be a value in
	//     the range 0-1023.
	//   - Keys belonging to the same group can be cached in the
	//     HSM local memory through the hsm_manage_key_group API.
	hsm_key_group_t key_group;
	//!< bitmap specifying the operation properties.
	hsm_op_import_key_flags_t flags;
	//!< Key lifetime attribute (PSA values):
	//   0x00 Volatile.
	//   0x01 Persistent.
	//   0x80 Volatile and permanent (Implementation defined value).
	//   0x81 Persistent and permanent (Implementation defined value).
	hsm_key_lifetime_t key_lifetime;
	//!< indicates the usage attributes of the key to be imported.
	hsm_key_usage_t key_usage;
	//!< indicates the type of the key to be imported.
	//   this is remained there to be backwork-compatible.
	hsm_key_type_t key_type;
	//!< Key size attribute. It represents the key security size in bits.
	hsm_bit_key_sz_t bit_key_sz;
	//!< Permitted algorithm attribute (PSA values)
	hsm_permitted_algo_t permitted_algo;
	//!< It is derived from key_type.
	hsm_psa_key_type_t psa_key_type;
	//!< LSB of the address in the requester space where the key can be
	//   found. This address is combined with the 32 bits MSBI extension
	//   provided for the service flow.
	//
	uint8_t *encryted_prv_key;
} op_import_key_args_t;

//!<   For a key encrypted by a KEK, the input format must be:
//     LSB |                             | MSG
//     ---------------------------------------
//     IV  |   Cipher text (private key) | TAG
struct kek_encr_key_fmt_t {
	uint8_t *iv;
	uint8_t *cipher_text;
	uint8_t *tag;
};

/**
 * This command is designed to perform the following operations:
 *  - import a key creating a new key identifier (import and create)
 *  - import a key using an existing key identifier (import and update)
 *  - delete an existing key
 *
 * The key encryption key (KEK) can be previously pre-shared or stored in the
 * key store.
 *
 * If the key to be imported is encrypted by using the KEK, it must have followed:
 *  - Algorithm: AES GCM
 *  - KEK Key could be:
 *    -- part-unique root KEK,
 *    -- the common root KEK,
 *    -- derived KEK or imported previouslyroot KEK
 *  - AAD = 0
 *  - IV = 12 bytes. When encrypting with a given key, the same IV MUST NOT be
 *    repeated. Refer to SP 800-38D for recommendations.
 *  - Tag = 16 bytes
 *  - cipher_text: key to be imported
 *
 * For a key wrapped with provisioned wrap key,
 * attributes (lifetime, usage, type, size, permitted algorithm)
 * must not be set in the command message.
 *
 * User can call this function only after having opened a key management service
 * flow
 *
 * \param key_management_hdl handle identifying the key management service flow.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */

hsm_err_t hsm_import_key(hsm_hdl_t key_management_hdl,
			 op_import_key_args_t *args);
#endif
