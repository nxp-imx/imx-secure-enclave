// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025-2026 NXP
 */

#ifndef HSM_GET_EVENT_H
#define HSM_GET_EVENT_H

#include "hsm_handle.h"
#include "hsm_utils.h"

/**
 *  @defgroup group34 GET EVENT
 * @{
 */

#define MAX_NUM_EVENT_REPORT	8

typedef struct {
	uint16_t event_rsp_code;
	//!< Response code helps identify the reason for reporting the event.
	uint8_t event_cmd_id;
	//!< Command Id, for which event is reported.
	uint8_t event_ipc_id;
	//!< IPC Id(0x01 = MU RTD, 0x02 = MU APPS), for which event is reported.
} hsm_event_report_info_t;

/**
 * Structure specifying the members that will enable reporting first 'n' FW's events,
 * where n is defined by the macro 'MAX_NUM_EVENT_REPORT'.
 */
typedef struct {
	uint16_t num_event_report;
	//!< Number of events reported since the last power cycle.
	hsm_event_report_info_t hsm_event_report_list[MAX_NUM_EVENT_REPORT];
	//!< List of events reported since the last power cycle.
} op_get_event_msg_args_t;

/**
 * This API will report FW's first 'n' reported events, where n is defined by
 * the macro 'MAX_NUM_EVENT_REPORT'.
 *
 * \param session_hdl handle identifying the session handle.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_get_event(hsm_hdl_t session_hdl,
			op_get_event_msg_args_t *args);

/** @} end of GET EVENT  operation */
#endif //HSM_GET_EVENT_H
