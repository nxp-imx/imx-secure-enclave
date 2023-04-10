/*
 * Copyright 2023 NXP
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

#include <string.h>

#include "internal/hsm_session.h"

#include "sab_session.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_session_open_req(void *phdl,
				      void *cmd_buf, void *rsp_buf,
				      uint32_t *cmd_msg_sz,
				      uint32_t *rsp_msg_sz,
				      uint32_t msg_hdl,
				      void *args)
{
	uint32_t ret = 0;
	struct sab_cmd_session_open_msg *cmd =
		(struct sab_cmd_session_open_msg *)cmd_buf;
	open_session_args_t *op_args = (open_session_args_t *)args;

		cmd->mu_id = op_args->mu_id;
		cmd->interrupt_idx = op_args->interrupt_idx;
		cmd->tz = op_args->tz;
		cmd->did = op_args->did;
		cmd->priority = op_args->session_priority;
		cmd->operating_mode = op_args->operating_mode;

	*cmd_msg_sz = sizeof(struct sab_cmd_session_open_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_session_open_rsp);

	return ret;
}

uint32_t proc_msg_rsp_session_open_req(void *rsp_buf, void *args)
{
	struct sab_cmd_session_open_rsp *rsp =
		(struct sab_cmd_session_open_rsp *)rsp_buf;
	open_session_args_t *op_args = (open_session_args_t *)args;

	op_args->session_hdl = rsp->session_handle;

	return SAB_SUCCESS_STATUS;
}

uint32_t prepare_msg_session_close_req(void *phdl,
				       void *cmd_buf, void *rsp_buf,
				       uint32_t *cmd_msg_sz,
				       uint32_t *rsp_msg_sz,
				       uint32_t msg_hdl,
				       void *args)
{
	uint32_t ret = 0;
	struct sab_cmd_session_close_msg *cmd =
		(struct sab_cmd_session_close_msg *)cmd_buf;

	*cmd_msg_sz = sizeof(struct sab_cmd_session_close_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_session_close_rsp);

	cmd->session_handle = msg_hdl;

	return ret;
}

uint32_t proc_msg_rsp_session_close_req(void *rsp_buf, void *args)
{
	return SAB_SUCCESS_STATUS;
}
