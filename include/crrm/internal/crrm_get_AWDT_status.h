// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#ifndef CRRM_GET_AWDT_STATUS_H
#define CRRM_GET_AWDT_STATUS_H

#include "internal/crrm_handle.h"

/**
 *  @defgroup group2 Get AWDT status
 * @{
 */

#define TIMER_INFO_SIZE			16
#define AWDT_TIMER_STATUS_SIZE		sizeof(AWDT_timer)

/**
 * Structure describing AWDT timer status parameters
 */
typedef struct {
	uint8_t initialized;
	//!< 0 = not initialized, 1 = initialized
	uint8_t running;
	//!< 0 = not running, 1 = running
	uint16_t BBSM_running;
	//!< 0 = not running, 1 = running
	uint32_t curr_timer_value;
	//!< current timer value in ms
	uint32_t safety_period;
	//!< safety period in ms
	uint32_t max_timer_value;
	//!< max timer value in ms
	uint32_t BBSM_timer_value;
	//!< stored timer value in ms
	uint16_t timer_info_len;
	//!< length of timerInfo
	uint8_t timer_info[];
	//!< variable-length timerInfo data
} AWDT_timer;

/**
 * Structure describing the get status operation member arguments
 */
typedef struct {
	uint8_t timer_id;
	//!< timer id
	uint8_t *addr;
	//!< AWDT status report address
	uint32_t input_size;
	//!< AWDT status report size
	uint32_t output_size;
	//!< AWDT status report size provided by FW
	AWDT_timer *status;
	//!< status of timer with id timer_id
} op_get_AWDT_status_args_t;

/**
 * Perform get AWDT status operation\n
 * User can call this function only after CRRM init has been done.\n
 * Get CRRM handle before calling this API.\n
 * This API request a status report for a given timer.\n
 * The status data will be output to the memory address provided.
 * If the buffer to copy this data is too small, no data will be copied.
 *
 * \param crrm_hdl handle identifying the current session.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */

crrm_err_t crrm_get_AWDT_status(crrm_hdl_t crrm_hdl, op_get_AWDT_status_args_t *args);

/** @} end of AWDT Get status operation */
#endif
