// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
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
	uint32_t ret = SAB_ENGN_PASS;
	struct sab_cmd_delete_key_msg *cmd =
		(struct sab_cmd_delete_key_msg *) cmd_buf;
	op_delete_key_args_t *op_args = (op_delete_key_args_t *) args;

	if (!op_args)
		return SAB_ENGN_FAIL;

	cmd->key_management_hdl = msg_hdl;
	cmd->key_identifier = op_args->key_identifier;
	cmd->flags = op_args->flags;

	*cmd_msg_sz = sizeof(struct sab_cmd_delete_key_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_delete_key_rsp);

	return ret;
}

uint32_t proc_msg_rsp_del_key(void *rsp_buf, void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);

	return err;
}
