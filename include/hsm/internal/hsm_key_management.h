// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef HSM_KEY_MANAGEMENT_H
#define HSM_KEY_MANAGEMENT_H

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"

/**
 *  @defgroup group3 Key management
 * @{
 */

/**
 * Bitmap specifying the key management service supported properties
 */
typedef uint8_t hsm_svc_key_management_flags_t;

/**
 * Structure detailing the key management open service member arguments
 */
typedef struct {
	hsm_hdl_t key_management_hdl;
	//!< handle identifying the key management service flow
	hsm_svc_key_management_flags_t flags;
	//!< bitmap specifying the services properties.
} open_svc_key_management_args_t;

/**
 * Open a key management service flow\n
 * User must open this service flow in order to perform operation on the
 * key store keys (generate, update, delete)
 *
 * \param key_store_hdl handle identifying the key store service flow.
 * \param args pointer to the structure containing the function arguments.
 * \param key_management_hdl pointer to where the key management service flow
 * handle must be written.
 *
 * \return error_code error code.
 */
hsm_err_t hsm_open_key_management_service(hsm_hdl_t key_store_hdl,
					  open_svc_key_management_args_t *args,
					  hsm_hdl_t *key_management_hdl);

/**
 * Terminate a previously opened key management service flow
 *
 * \param key_management_hdl handle identifying the key management service flow.
 *
 * \return error code
 */
hsm_err_t hsm_close_key_management_service(hsm_hdl_t key_management_hdl);

/** @} end of key management service flow */

#endif
