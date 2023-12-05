// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "internal/hsm_key.h"
#include "internal/hsm_manage_key_group.h"

#include "sab_manage_key_group.h"
#include "sab_messaging.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_manage_key_group(void *phdl,
				      void *cmd_buf, void *rsp_buf,
				      uint32_t *cmd_msg_sz,
				      uint32_t *rsp_msg_sz,
				      uint32_t msg_hdl,
				      void *args)
{
	uint32_t ret = SAB_ENGN_PASS;
	struct sab_cmd_manage_key_group_msg *cmd =
		(struct sab_cmd_manage_key_group_msg *)cmd_buf;
	op_manage_key_group_args_t *op_args = (op_manage_key_group_args_t *)args;

	if (!op_args)
		return SAB_ENGN_FAIL;

	cmd->key_management_handle = msg_hdl;
	cmd->flags = op_args->flags;
	cmd->key_group = op_args->key_group;
	cmd->rsv = 0;

	*cmd_msg_sz = sizeof(struct sab_cmd_manage_key_group_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_manage_key_group_rsp);

	return ret;
}

uint32_t proc_msg_rsp_manage_key_group(void *rsp_buf, void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);

	return err;
}
