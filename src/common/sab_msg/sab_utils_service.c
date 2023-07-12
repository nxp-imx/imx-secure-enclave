// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "sab_messaging.h"
#include "sab_utils_service.h"
#include "internal/she_utils_service.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_open_utils(void *phdl,
				void *cmd_buf, void *rsp_buf,
				uint32_t *cmd_msg_sz,
				uint32_t *rsp_msg_sz,
				uint32_t msg_hdl,
				void *args)
{
	uint32_t ret = SAB_ENGN_PASS;
	struct sab_cmd_open_utils_msg *cmd =
		(struct sab_cmd_open_utils_msg *)cmd_buf;

	cmd->input_address_ext = 0;
	cmd->output_address_ext = 0;
	cmd->key_store_handle = msg_hdl;

	*cmd_msg_sz = sizeof(struct sab_cmd_open_utils_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_open_utils_rsp);

	return ret;
}

uint32_t proc_msg_rsp_open_utils(void *rsp_buf, void *args)
{
	op_open_utils_args_t *op_args =
		(op_open_utils_args_t *)args;
	struct sab_cmd_open_utils_rsp *rsp =
		(struct sab_cmd_open_utils_rsp *)rsp_buf;

	if (!op_args)
		return SAB_FAILURE_STATUS;

	if (rsp->rsp_code != SAB_SUCCESS_STATUS)
		return rsp->rsp_code;

	op_args->utils_handle = rsp->utils_handle;

	return SAB_SUCCESS_STATUS;
}

uint32_t prepare_msg_close_utils(void *phdl,
				 void *cmd_buf,
				 void *rsp_buf,
				 uint32_t *cmd_msg_sz,
				 uint32_t *rsp_msg_sz,
				 uint32_t msg_hdl,
				 void *args)
{
	uint32_t ret = SAB_ENGN_PASS;
	struct sab_cmd_close_utils_msg *cmd =
		(struct sab_cmd_close_utils_msg *)cmd_buf;

	*cmd_msg_sz = sizeof(struct sab_cmd_close_utils_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_close_utils_rsp);

	cmd->utils_handle = msg_hdl;

	return ret;
}

uint32_t proc_msg_rsp_close_utils(void *rsp_buf, void *args)
{
	return SAB_SUCCESS_STATUS;
}
