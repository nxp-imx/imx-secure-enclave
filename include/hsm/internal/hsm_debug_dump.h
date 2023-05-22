// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#ifndef HSM_DEBUG_DUMP_H
#define HSM_DEBUG_DUMP_H

#include <stdbool.h>
#include <stdint.h>

#include "hsm_handle.h"
#include "hsm_utils.h"

#define MAC_BUFF_LEN	20

/**
 *  @defgroup group28 Dump Firmware Log
 * @{
 */

/**
 * Structure detailing the debug dump operation member arguments
 */
typedef struct {
	bool is_dump_pending;
	uint32_t dump_buf_len;
	uint32_t dump_buf[MAC_BUFF_LEN];
} op_debug_dump_args_t;

/**
 * This command is designed to dump the firmware logs
 *
 * \param session_hdl handle identifying the session handle.
 *
 * \return error code
 */

hsm_err_t dump_firmware_log(hsm_hdl_t session_hdl);

/** @} end of dump firmawre log operation */
#endif
