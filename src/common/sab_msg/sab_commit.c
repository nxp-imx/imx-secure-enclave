// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include "internal/hsm_commit.h"

#include "sab_commit.h"

uint32_t prepare_msg_commit(void *phdl, void *cmd_buf, void *rsp_buf,
			    uint32_t *cmd_msg_sz, uint32_t *rsp_msg_sz,
			    uint32_t msg_hdl, void *args)
{
	struct rom_cmd_commit_msg *cmd = (struct rom_cmd_commit_msg *)cmd_buf;
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_CMD_MSG_PREP_FAIL);
	op_commit_args_t *op_args = (op_commit_args_t *)args;

	/* Validate input arguments */
	if (!op_args)
		return err;

	/* Set message sizes */
	*cmd_msg_sz = sizeof(struct rom_cmd_commit_msg);
	*rsp_msg_sz = sizeof(struct rom_cmd_commit_rsp);

	/* Fill command data */
	cmd->info_type = op_args->info_type;

	return SAB_LIB_STATUS(SAB_LIB_SUCCESS);
}

uint32_t proc_msg_rsp_commit(void *rsp_buf, void *args)
{
	struct rom_cmd_commit_rsp *rsp = (struct rom_cmd_commit_rsp *)rsp_buf;
	op_commit_args_t *op_args = (op_commit_args_t *)args;
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);

	/* Extract committed information from response */
	op_args->committed_info = rsp->committed_info;

	return err;
}
