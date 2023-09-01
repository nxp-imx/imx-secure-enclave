// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
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
	uint32_t ret = SAB_LIB_STATUS(SAB_LIB_SUCCESS);
	struct sab_cmd_session_open_msg *cmd =
		(struct sab_cmd_session_open_msg *)cmd_buf;
	open_session_args_t *op_args = (open_session_args_t *)args;

	if (!op_args)
		return SAB_LIB_STATUS(SAB_LIB_CMD_MSG_PREP_FAIL);

#ifndef PSA_COMPLIANT
		cmd->mu_id = op_args->mu_id;
		cmd->tz = op_args->tz;
		cmd->did = op_args->did;
#endif
		cmd->interrupt_idx = op_args->interrupt_idx;
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

	if (!op_args)
		return SAB_LIB_STATUS(SAB_LIB_CMD_MSG_PREP_FAIL);

	op_args->session_hdl = rsp->session_handle;

	return SAB_LIB_STATUS(SAB_LIB_SUCCESS);
}

uint32_t prepare_msg_session_close_req(void *phdl,
				       void *cmd_buf, void *rsp_buf,
				       uint32_t *cmd_msg_sz,
				       uint32_t *rsp_msg_sz,
				       uint32_t msg_hdl,
				       void *args)
{
	uint32_t ret = SAB_LIB_STATUS(SAB_LIB_SUCCESS);
	struct sab_cmd_session_close_msg *cmd =
		(struct sab_cmd_session_close_msg *)cmd_buf;

	*cmd_msg_sz = sizeof(struct sab_cmd_session_close_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_session_close_rsp);

	cmd->session_handle = msg_hdl;

	return ret;
}

uint32_t proc_msg_rsp_session_close_req(void *rsp_buf, void *args)
{
	return SAB_LIB_STATUS(SAB_LIB_SUCCESS);
}
