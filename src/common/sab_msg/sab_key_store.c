// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "internal/hsm_key_store.h"

#include "sab_key_store.h"

uint32_t prepare_msg_key_store_open_req(void *phdl,
					void *cmd_buf, void *rsp_buf,
					uint32_t *cmd_msg_sz,
					uint32_t *rsp_msg_sz,
					uint32_t msg_hdl,
					void *args)
{
	uint32_t ret = SAB_ENGN_PASS;
	struct sab_cmd_key_store_open_msg *cmd =
		(struct sab_cmd_key_store_open_msg *)cmd_buf;
	open_svc_key_store_args_t *op_args =
		(open_svc_key_store_args_t *)args;

	if (!op_args)
		return SAB_ENGN_FAIL;

	cmd->session_handle = msg_hdl;
	cmd->key_store_id = op_args->key_store_identifier;
	cmd->password = op_args->authentication_nonce;
	cmd->flags = op_args->flags;
#ifndef PSA_COMPLIANT
	cmd->max_updates = op_args->max_updates_number;
	cmd->min_mac_length = op_args->min_mac_length;
#endif

	*cmd_msg_sz = sizeof(struct sab_cmd_key_store_open_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_key_store_open_rsp);

	return ret;
}

uint32_t proc_msg_rsp_key_store_open_req(void *rsp_buf, void *args)
{
	struct sab_cmd_key_store_open_rsp *rsp =
		(struct sab_cmd_key_store_open_rsp *)rsp_buf;
	open_svc_key_store_args_t *op_args =
		(open_svc_key_store_args_t *)args;

	if (!op_args)
		return SAB_FAILURE_STATUS;

	op_args->key_store_hdl = rsp->key_store_handle;

	return SAB_SUCCESS_STATUS;
}

uint32_t prepare_msg_key_store_close_req(void *phdl,
					 void *cmd_buf, void *rsp_buf,
					 uint32_t *cmd_msg_sz,
					 uint32_t *rsp_msg_sz,
					 uint32_t msg_hdl,
					 void *args)
{
	uint32_t ret = SAB_ENGN_PASS;
	struct sab_cmd_key_store_close_msg *cmd =
		(struct sab_cmd_key_store_close_msg *)cmd_buf;

	cmd->key_store_handle = msg_hdl;

	*cmd_msg_sz = sizeof(struct sab_cmd_key_store_close_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_key_store_close_rsp);

	return ret;
}

uint32_t proc_msg_rsp_key_store_close_req(void *rsp_buf, void *args)
{
	return SAB_SUCCESS_STATUS;
}
