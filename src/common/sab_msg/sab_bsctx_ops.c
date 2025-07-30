// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include "internal/hsm_bsctx_ops.h"

#include "sab_bsctx_ops.h"
#include "sab_messaging.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_bsctx_ops(void *phdl, void *cmd_buf, void *rsp_buf,
			       uint32_t *cmd_msg_sz, uint32_t *rsp_msg_sz,
			       uint32_t msg_hdl, void *args)
{
	struct rom_cmd_bsctx_ops_msg *cmd =
		(struct rom_cmd_bsctx_ops_msg *)cmd_buf;
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_CMD_MSG_PREP_FAIL);
	op_boot_stage_ctx_args_t *op_args = args;

	if (!op_args)
		return err;

	cmd->op_code = op_args->op_code;
	cmd->bs_ctx_val = op_args->bs_ctx_val;

	*cmd_msg_sz = sizeof(struct rom_cmd_bsctx_ops_msg);
	*rsp_msg_sz = sizeof(struct rom_cmd_bsctx_ops_rsp);

	return SAB_LIB_STATUS(SAB_LIB_SUCCESS);
}

uint32_t proc_msg_rsp_bsctx_ops(void *rsp_buf, void *args)
{
	struct rom_cmd_bsctx_ops_rsp *rsp =
		(struct rom_cmd_bsctx_ops_rsp *)rsp_buf;
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);
	op_boot_stage_ctx_args_t *op_args = args;

	if (op_args)
		op_args->bs_ctx_val = rsp->bs_ctx_val;

	return err;
}
