/*
 * Copyright 2023 NXP
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

#ifndef HSM_GET_KEY_ATTR_H
#define HSM_GET_KEY_ATTR_H

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "hsm_handle.h"
#include "hsm_utils.h"
#include "hsm_key.h"

typedef struct {
	//!< identifier of the key to be used for the operation.
	uint32_t *key_identifier;
	//!< indicates which type of key must be generated.
	hsm_key_type_t key_type;
	hsm_bit_key_sz_t bit_key_sz;
	hsm_key_lifetime_t key_lifetime;
	hsm_key_usage_t key_usage;
	hsm_permitted_algo_t permitted_algo;
	hsm_key_lifecycle_t lifecycle;
} op_get_key_attr_args_t;

/**
 * This command is designed to perform the following operations:
 *  - get attributes of an existing key
 *
 * \param key_importment_hdl handle identifying the key management service flow.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */

hsm_err_t hsm_get_key_attr(hsm_hdl_t key_management_hdl,
			   op_get_key_attr_args_t *args);

#endif
