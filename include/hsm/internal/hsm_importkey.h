// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#ifndef HSM_IMPORT_KEY_H
#define HSM_IMPORT_KEY_H

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"

/**
 *  @defgroup group3 Key management
 * @{
 */

/**
 * Bitmap specifying the import key operation supported properties
 * Bit 0: Defines input configuration
 * Bit 1-6: Reserved
 * Bit 7: Strict
 */
typedef uint8_t hsm_op_import_key_flags_t;

#define HSM_OP_IMPORT_KEY_INPUT_E2GO_TLV \
	((hsm_op_import_key_flags_t)(1u << 0))
//!< Bit 0: set 1 means input is E2GO_TLV.

#define HSM_OP_IMPORT_KEY_INPUT_ELE_TLV \
	((hsm_op_import_key_flags_t)(0u << 0))
//!< Bit 0: set 0 means input is ELE TLV.

#define HSM_OP_IMPORT_KEY_FLAGS_AUTOMATIC_GROUP \
	((hsm_op_import_key_flags_t)(0u << 2))
//!< Bit 2: set 0 means ELE automatically choose key group.

#define HSM_OP_IMPORT_KEY_FLAGS_GROUP_FIELD \
	((hsm_op_import_key_flags_t)(1u << 2))
//!< Bit 2: set 1 means ELE store key in key group set by key group field.
//
#define HSM_OP_IMPORT_KEY_FLAGS_STRICT_OPERATION \
	((hsm_op_import_key_flags_t)(1u << 7))
//!< Bit 7: Strict: Request completed - New key written to NVM with updated MC.

/**
 * Structure detailing the import key operation member arguments
 */
typedef struct {
	uint32_t  key_identifier;
	//!< Identifier of the KEK used to encrypt the key to be imported
	//!< (Ignored if KEK is not used as set as part of "flags" field).
	uint8_t   *input_lsb_addr;
	//!< Address in the requester space where:
	//!< - EdgeLock 2GO TLV can be found.
	//!< - Ignore this field if not E2GO_TLV.
	uint32_t  input_size;
	//!< Size in bytes of:
	//!< - EdgeLock 2GO TLV can be found.
	//!< - ELE TLV can be found.
	hsm_op_import_key_flags_t flags;
	//!< bitmap specifying the operation properties.
	uint16_t key_group;
	//!< In case of import key ELE option:
	//!< - The imported key group.
	//!< - Ignore this field if not ELE option.
} op_import_key_args_t;

/**
 * This API will be used to Import the key \n
 *
 * \param key_management_hdl handle identifying the key management service flow.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_import_key(hsm_hdl_t key_management_hdl,
			 op_import_key_args_t *args);
/** @} end of key management service flow */
#endif
