// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "sab_get_event.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_get_event(void *phdl, void *cmd_buf, void *rsp_buf,
			       uint32_t *cmd_msg_sz, uint32_t *rsp_msg_sz,
			       uint32_t msg_hdl, void *args)
{
	*cmd_msg_sz = sizeof(struct rom_cmd_get_event_msg);
	*rsp_msg_sz = sizeof(struct rom_cmd_get_event_rsp);

	return SAB_LIB_STATUS(SAB_LIB_SUCCESS);
}

uint32_t proc_msg_rsp_get_event(void *rsp_buf, void *args)
{
	struct rom_cmd_get_event_rsp *rsp =
			(struct rom_cmd_get_event_rsp *)rsp_buf;
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_RSP_PROC_FAIL);
	op_get_event_msg_args_t *op_args = args;
	uint32_t ret;

	op_args->num_event_report = rsp->event_count;

	if (!op_args->num_event_report)
		return err;

	if (op_args->num_event_report > MAX_NUM_EVENT_REPORT)
		return err;

	ret = plat_os_abs_memcpy_v2((uint8_t *)op_args->hsm_event_report_list,
				    (uint8_t *)rsp->event_info,
				    rsp->event_count << 2);
	if (ret != PLAT_SUCCESS) {
		err |= ret;
		return err;
	}

	return SAB_LIB_STATUS(SAB_LIB_SUCCESS);
}
