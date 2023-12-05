// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "sab_messaging.h"
#include "sab_get_status.h"
#include "internal/she_get_status.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_get_status(void *phdl,
				void *cmd_buf, void *rsp_buf,
				uint32_t *cmd_msg_sz,
				uint32_t *rsp_msg_sz,
				uint32_t msg_hdl,
				void *args)
{
	uint32_t ret = SAB_ENGN_PASS;
	struct sab_cmd_get_status_msg *cmd =
		(struct sab_cmd_get_status_msg *)cmd_buf;

	cmd->utils_handle = msg_hdl;

	*cmd_msg_sz = sizeof(struct sab_cmd_get_status_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_get_status_rsp);

	return ret;
}

uint32_t proc_msg_rsp_get_status(void *rsp_buf, void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);
	op_get_status_args_t *op_args =
		(op_get_status_args_t *)args;
	struct sab_cmd_get_status_rsp *rsp =
		(struct sab_cmd_get_status_rsp *)rsp_buf;

	if (!op_args) {
		err = SAB_LIB_STATUS(SAB_LIB_RSP_PROC_FAIL);
		goto exit;
	}

	if (GET_STATUS_CODE(rsp->rsp_code) == SAB_FAILURE_STATUS)
		goto exit;

	op_args->sreg = rsp->sreg;
exit:
	return err;
}
