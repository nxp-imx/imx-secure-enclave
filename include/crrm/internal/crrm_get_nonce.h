// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#ifndef CRRM_GET_NONCE_H
#define CRRM_GET_NONCE_H

#include "internal/crrm_handle.h"

/**
 *  @defgroup group3 Get Nonce
 * @{
 */

#define NONCE_DATA_SIZE			32

/**
 * Structure describing nonce info parameters
 */
typedef struct {
	uint8_t nonce_data[NONCE_DATA_SIZE];
	//!< nonce data
	uint8_t timer_info[];
	//!< variable-length timerInfo data
} nonce_info;

/**
 * Structure describing the get nonce operation member arguments
 */
typedef struct {
	uint8_t timer_id;
	//!< timer id
	uint8_t *nonce_addr;
	//!< nonce info address
	uint32_t nonce_size;
	//!< nonce info input size
	uint32_t output_size;
	//!< nonce info size provided by FW
	nonce_info *info;
	//!< nonce information (nonce data + timer info)
} op_get_nonce_args_t;

/**
 * Perform get nonce operation\n
 * User can call this function only after CRRM init has been done.\n
 * Get CRRM handle before calling this API.\n
 * This API request a new nonce value for a given timer.\n
 * This nonce value will invalidate any previous nonce values for the given timer.\n
 * The nonce plus programmed timerInfo will be output.\n
 * Note that if the buffer to copy this data is too small,
 * no data will be copied but the nonce will still be updated inside the Sentinel.
 *
 * \param crrm_hdl handle identifying the current session.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */

crrm_err_t crrm_get_nonce(crrm_hdl_t crrm_hdl, op_get_nonce_args_t *args);

/** @} end of get nonce operation */
#endif
