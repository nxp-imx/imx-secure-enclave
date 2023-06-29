// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "sab_messaging.h"
#include "sab_shared_buf.h"
#include "internal/she_shared_buf.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_shared_buf(void *phdl,
				void *cmd_buf, void *rsp_buf,
				uint32_t *cmd_msg_sz,
				uint32_t *rsp_msg_sz,
				uint32_t msg_hdl,
				void *args)
{
	uint32_t ret = SAB_ENGN_PASS;
	struct sab_cmd_shared_buf_msg *cmd =
		(struct sab_cmd_shared_buf_msg *)cmd_buf;

	cmd->session_handle = msg_hdl;

	*cmd_msg_sz = sizeof(struct sab_cmd_shared_buf_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_shared_buf_rsp);

	return ret;
}

uint32_t proc_msg_rsp_shared_buf(void *rsp_buf, void *args)
{
	op_shared_buf_args_t *op_args =
		(op_shared_buf_args_t *)args;
	struct sab_cmd_shared_buf_rsp *rsp =
		(struct sab_cmd_shared_buf_rsp *)rsp_buf;

	if (!op_args)
		return SAB_FAILURE_STATUS;

	if (rsp->rsp_code != SAB_SUCCESS_STATUS)
		return rsp->rsp_code;

	op_args->shared_buf_offset = rsp->shared_buf_offset;
	op_args->shared_buf_size = rsp->shared_buf_size;

	return SAB_SUCCESS_STATUS;
}
