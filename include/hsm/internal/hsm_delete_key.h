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

#ifndef HSM_DELETE_KEY_H
#define HSM_DELETE_KEY_H

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "hsm_handle.h"
#include "hsm_utils.h"
#include "hsm_key.h"

typedef uint8_t hsm_op_delete_key_flags_t;

typedef struct {
	//!< identifier of the key to be used for the operation.
	uint32_t key_identifier;
	//!< bitmap specifying the operation properties.
	hsm_op_delete_key_flags_t flags;
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

#endif
