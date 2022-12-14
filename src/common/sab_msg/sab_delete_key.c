/*
 * Copyright 2022 NXP
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

#include "internal/hsm_delete_key.h"

#include "sab_delete_key.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_del_key(void *phdl,
			       void *cmd_buf, void *rsp_buf,
			       uint32_t *cmd_msg_sz,
			       uint32_t *rsp_msg_sz,
			       uint32_t msg_hdl,
			       void *args)
{
	uint32_t ret = 0;
	struct sab_cmd_delete_key_msg *cmd =
		(struct sab_cmd_delete_key_msg *) cmd_buf;
	struct sab_cmd_delete_key_rsp *rsp =
		(struct sab_cmd_delete_key_rsp *) rsp_buf;
	op_delete_key_args_t *op_args = (op_delete_key_args_t *) args;

	cmd->key_management_hdl = msg_hdl;
	cmd->key_identifier = op_args->key_identifier;
	cmd->flags = op_args->flags;

	*cmd_msg_sz = sizeof(struct sab_cmd_delete_key_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_delete_key_rsp);

	return ret;
}

uint32_t proc_msg_rsp_del_key(void *rsp_buf, void *args)
{
	op_delete_key_args_t *op_args = (op_delete_key_args_t *) args;
	struct sab_cmd_delete_key_rsp *rsp =
		(struct sab_cmd_delete_key_rsp *) rsp_buf;

	return SAB_SUCCESS_STATUS;
}
