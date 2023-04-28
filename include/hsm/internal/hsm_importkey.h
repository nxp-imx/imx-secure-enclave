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
typedef uint8_t hsm_op_import_key_flags_t;

//!< Bit 0: Defines input configuration.
//   - set 1 means input is E2GO_TLV
//   - set 0 means input is signed message.
#define HSM_OP_IMPORT_KEY_INPUT_E2GO_TLV \
	((hsm_op_import_key_flags_t)(1u << 0))

#define HSM_OP_IMPORT_KEY_INPUT_SIGNED_MSG \
	((hsm_op_import_key_flags_t)(0u << 0))
//!< Bit 1-6: Reserved.

//!< Bit 7: Strict: Request completed - New key written to NVM with updated MC.
#define HSM_OP_IMPORT_KEY_FLAGS_STRICT_OPERATION \
	((hsm_op_import_key_flags_t)(1u << 7))

typedef struct {
	//!< Identifier of the KEK used to encrypt the key to be imported
	//   (Ignored if KEK is not used as set as part of "flags" field).
	uint32_t  key_identifier;
	//!< Address in the requester space where:
	//   - EdgeLock 2GO TLV can be found.
	//   - Ignore this field if not E2GO_TLV.
	uint8_t   *input_lsb_addr;
	//!< Size in bytes of:
	//   - EdgeLock 2GO TLV can be found.
	//   - Ignore this field if not E2GO_TLV.
	uint32_t  input_size;
	//!< bitmap specifying the operation properties.
	hsm_op_import_key_flags_t flags;
} op_import_key_args_t;

hsm_err_t hsm_import_key(hsm_hdl_t key_management_hdl,
			 op_import_key_args_t *args);
/** @} end of key management service flow */
#endif
