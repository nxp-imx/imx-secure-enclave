// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "internal/hsm_dev_write_fuse.h"

#include "sab_dev_write_fuse.h"
#include "sab_messaging.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_dev_write_fuse(void *phdl, void *cmd_buf, void *rsp_buf,
				    uint32_t *cmd_msg_sz, uint32_t *rsp_msg_sz,
				    uint32_t msg_hdl, void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_CMD_MSG_PREP_FAIL);
	struct sab_cmd_dev_write_fuse_msg *cmd =
		(struct sab_cmd_dev_write_fuse_msg *)cmd_buf;
	op_dev_write_fuse_args_t *op_args = (op_dev_write_fuse_args_t *)args;

	cmd->bit_pos = op_args->bit_pos;
	cmd->bit_len = op_args->bit_len;
	cmd->payload1 = op_args->payload1;
	cmd->payload2 = op_args->payload2;
	cmd->payload3 = op_args->payload3;
	cmd->payload4 = op_args->payload4;

	*rsp_msg_sz = sizeof(struct sab_cmd_dev_write_fuse_rsp);
	*cmd_msg_sz = sizeof(struct sab_cmd_dev_write_fuse_msg);

	err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);

	return err;
}

uint32_t proc_msg_rsp_dev_write_fuse(void *rsp_buf, void *args)
{
	op_dev_write_fuse_args_t *op_args = (op_dev_write_fuse_args_t *)args;
	struct sab_cmd_dev_write_fuse_rsp *rsp =
		(struct sab_cmd_dev_write_fuse_rsp *)rsp_buf;

	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);

	if (GET_STATUS_CODE(rsp->rsp_code) == SAB_FAILURE_STATUS)
		return err;

	op_args->processed_idx = rsp->processed_idx;

	return err;
}
