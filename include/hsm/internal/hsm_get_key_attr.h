// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef HSM_GET_KEY_ATTR_H
#define HSM_GET_KEY_ATTR_H

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

/**
 * Structure describing the get key attribute operation arguments
 */
typedef struct {
	uint32_t key_identifier;
	//!< identifier of the key to be used for the operation.
	hsm_key_type_t key_type;
	//!< indicates which type of key must be generated.
	hsm_bit_key_sz_t bit_key_sz;
	//!< indicates key security size in bits.
	hsm_key_lifetime_t key_lifetime;
	//!< this attribute comprises of two indicaters-key persistence level
	//!< and location where the key is stored.
	hsm_key_usage_t key_usage;
	//!< indicates the cryptographic operations that key can execute.
	hsm_permitted_algo_t permitted_algo;
	//!< indicates the key permitted algorithm.
	hsm_key_lifecycle_t lifecycle;
	//!< indicates the device lifecycle in which key is usable.
} op_get_key_attr_args_t;

/**
 * This command is designed to perform the following operations:
 *  - get attributes of an existing key
 *
 * \param key_management_hdl handle identifying the key management service flow.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */

hsm_err_t hsm_get_key_attr(hsm_hdl_t key_management_hdl,
			   op_get_key_attr_args_t *args);

/** @} end of key management service flow */
#endif
