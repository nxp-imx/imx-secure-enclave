// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "internal/hsm_key_management.h"

#include "sab_key_management.h"

uint32_t prepare_msg_key_management_open_req(void *phdl,
					     void *cmd_buf, void *rsp_buf,
					     uint32_t *cmd_msg_sz,
					     uint32_t *rsp_msg_sz,
					     uint32_t msg_hdl,
					     void *args)
{
	uint32_t ret = SAB_ENGN_PASS;
	struct sab_cmd_key_management_open_msg *cmd =
		(struct sab_cmd_key_management_open_msg *)cmd_buf;
	open_svc_key_management_args_t *op_args =
		(open_svc_key_management_args_t *)args;

	if (!op_args)
		return SAB_ENGN_FAIL;

	cmd->key_store_handle = msg_hdl;
	cmd->flags = op_args->flags;

	*cmd_msg_sz = sizeof(struct sab_cmd_key_management_open_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_key_management_open_rsp);

	return ret;
}

uint32_t proc_msg_rsp_key_management_open_req(void *rsp_buf, void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);
	struct sab_cmd_key_management_open_rsp *rsp =
		(struct sab_cmd_key_management_open_rsp *)rsp_buf;
	open_svc_key_management_args_t *op_args =
		(open_svc_key_management_args_t *)args;

	if (!op_args) {
		err = SAB_LIB_STATUS(SAB_LIB_RSP_PROC_FAIL);
		goto exit;
	}

	op_args->key_management_hdl = rsp->key_management_handle;
exit:
	return err;
}

uint32_t prepare_msg_key_management_close_req(void *phdl,
					      void *cmd_buf, void *rsp_buf,
					      uint32_t *cmd_msg_sz,
					      uint32_t *rsp_msg_sz,
					      uint32_t msg_hdl,
					      void *args)
{
	uint32_t ret = SAB_ENGN_PASS;
	struct sab_cmd_key_management_close_msg *cmd =
		(struct sab_cmd_key_management_close_msg *)cmd_buf;

	cmd->key_management_handle = msg_hdl;

	*cmd_msg_sz = sizeof(struct sab_cmd_key_management_close_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_key_management_close_rsp);

	return ret;
}

uint32_t proc_msg_rsp_key_management_close_req(void *rsp_buf, void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);

	return err;
}
