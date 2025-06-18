// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#ifndef CRRM_REFRESH_AWDT_H
#define CRRM_REFRESH_AWDT_H

#include "internal/hsm_utils.h"

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
 * User can call this function only after CRRM init has been done.
 *
 * \param crrm_hdl handle identifying the current session.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */

hsm_err_t crrm_refresh_AWDT(hsm_hdl_t crrm_hdl, op_refresh_AWDT_args_t *args);

/** @} end of refresh AWDT operation */
#endif
