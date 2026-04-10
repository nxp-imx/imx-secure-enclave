// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025-2026 NXP
 */

#ifndef CRRM_REFRESH_AWDT_H
#define CRRM_REFRESH_AWDT_H

#include "crrm_handle.h"

/**
 *  @defgroup group4 Refresh AWDT
 * @{
 */

#define NONCE_DATA_SIZE			32

/**
 * Structure describing signature data parameters to be signed
 */
typedef struct {
	uint8_t timer_id;
	//!< timer id
	uint8_t pub_key_index;
	//!< public key index
	uint16_t reserved;
	//!< reserved value
	uint32_t new_timer_value;
	//!< new value for timer
	uint8_t nonce_data[NONCE_DATA_SIZE];
	//!< nonce data
	uint8_t timer_info[];
	//!< variable-length timerInfo data
} signature_data;

/**
 * Structure describing request data parameters
 */
typedef struct {
	uint32_t new_timer_value;
	//!< new value for timer
	uint16_t signature_length;
	//!< length of signature field
	uint8_t signature[];
	//!< Signature calculated on the signature data
} request_data;

/**
 * Structure describing the refresh AWDT operation member arguments
 */
typedef struct {
	uint8_t timer_id;
	//!< timer id
	uint8_t pub_key_index;
	//!< public key index
	uint8_t *req_data_addr;
	//!< nonce info address
	uint32_t req_data_size;
	//!< nonce info input size
	uint32_t new_timer_value;
	//!< new value for timer
} op_refresh_AWDT_args_t;

/**
 * Perform refresh AWDT operation\n
 * User can call this function only after CRRM init has been done.\n
 * Get CRRM handle before calling this API.\n
 * This API is used to refresh the specified AWDT.\n
 * The message contains a signature,
 * that is calculated over the concatenation of the following information:\n
 * 1: word 1 of the message below (pub key index and timer ID)\n
 * 2: the newTimerValue from the request structure\n
 * 3: current nonce value for the requested timer\n
 * 4: timer info for the requested timer if present\n
 * If the signature is valid, the corresponding AWDT timer is refreshed
 *
 * \param crrm_hdl handle identifying the current session.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */

crrm_err_t crrm_refresh_AWDT(crrm_hdl_t crrm_hdl, op_refresh_AWDT_args_t *args);

/** @} end of refresh AWDT operation */
#endif
