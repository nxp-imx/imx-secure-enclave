// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#ifndef HSM_DELETE_KEY_H
#define HSM_DELETE_KEY_H

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
typedef uint8_t hsm_op_delete_key_flags_t;

typedef struct {
	uint32_t key_identifier;
	//!< identifier of the key to be used for the operation.
	hsm_op_delete_key_flags_t flags;
	//!< bitmap specifying the operation properties.
} op_delete_key_args_t;

/**
 * This command is designed to perform the following operations:
 *  - delete an existing key
 *
 * \param key_importment_hdl handle identifying the key management service flow.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */

hsm_err_t hsm_delete_key(hsm_hdl_t key_management_hdl,
			 op_delete_key_args_t *args);

//!< Bit 0-6: Reserved.
//!< Bit 7: Strict: Request completed - New key written to NVM with updated MC.
#define HSM_OP_DEL_KEY_FLAGS_STRICT_OPERATION \
	((hsm_op_import_key_flags_t)(1u << 7))

/** @} end of key management service flow */
#endif
