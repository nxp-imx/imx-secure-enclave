/*
 * Copyright 2022-2023 NXP
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
typedef struct {
	bool is_dump_pending;
	uint32_t dump_buf_len;
	uint32_t dump_buf[MAC_BUFF_LEN];
} op_debug_dump_args_t;

hsm_err_t dump_firmware_log(hsm_hdl_t session_hdl);

/** @} end of dump firmawre log operation */
#endif
