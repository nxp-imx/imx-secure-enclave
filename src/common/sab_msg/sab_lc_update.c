// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "internal/hsm_lc_update.h"

#include "sab_lc_update.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_fwd_lc_update(void *phdl,
				   void *cmd_buf, void *rsp_buf,
				   uint32_t *cmd_msg_sz,
				   uint32_t *rsp_msg_sz,
				   uint32_t msg_hdl,
				   void *args)
{
	uint32_t ret = 0;
	struct rom_cmd_lc_update_msg *cmd =
		(struct rom_cmd_lc_update_msg *) cmd_buf;
	op_lc_update_msg_args_t *op_args = (op_lc_update_msg_args_t *) args;

	cmd->new_lc_state = op_args->new_lc_state;

	*cmd_msg_sz = sizeof(struct rom_cmd_lc_update_msg);
	*rsp_msg_sz = sizeof(struct rom_cmd_lc_update_rsp);

	return ret;
}

uint32_t proc_msg_rsp_fwd_lc_update(void *rsp_buf, void *args)
{
	return SAB_SUCCESS_STATUS;
}

uint32_t prepare_msg_ret_lc_update(void *phdl,
				   void *cmd_buf, void *rsp_buf,
				   uint32_t *cmd_msg_sz,
				   uint32_t *rsp_msg_sz,
				   uint32_t msg_hdl,
				   void *args)
{
	return prepare_msg_fwd_lc_update(phdl, cmd_buf, rsp_buf,
					 cmd_msg_sz, rsp_msg_sz,
					 msg_hdl, args);
}

uint32_t proc_msg_rsp_ret_lc_update(void *rsp_buf, void *args)
{
	return SAB_SUCCESS_STATUS;
}
