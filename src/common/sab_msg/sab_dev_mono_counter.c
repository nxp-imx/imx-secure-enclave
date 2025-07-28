// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <stdio.h>

#include "internal/hsm_dev_mono_counter.h"

#include "sab_dev_mono_counter.h"
#include "sab_messaging.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_dev_mono_counter(void *phdl, void *cmd_buf, void *rsp_buf,
				      uint32_t *cmd_msg_sz, uint32_t *rsp_msg_sz,
				      uint32_t msg_hdl, void *args)
{
	struct sab_cmd_dev_mono_counter_msg *cmd =
		(struct sab_cmd_dev_mono_counter_msg *)cmd_buf;
	op_dev_mono_counter_args_t *op_args = (op_dev_mono_counter_args_t *)args;

	cmd->ele_hsm_fuse_word = op_args->ele_hsm_fuse_word;
	cmd->v2x_hsm_fuse_word = op_args->v2x_hsm_fuse_word;
	cmd->v2x_she_fuse_word = op_args->v2x_she_fuse_word;

	*rsp_msg_sz = sizeof(struct sab_cmd_dev_mono_counter_rsp);
	*cmd_msg_sz = sizeof(struct sab_cmd_dev_mono_counter_msg);

	return SAB_LIB_STATUS(SAB_LIB_SUCCESS);
}

uint32_t proc_msg_rsp_dev_mono_counter(void *rsp_buf, void *args)
{
	op_dev_mono_counter_args_t *op_args = (op_dev_mono_counter_args_t *)args;
	struct sab_cmd_dev_mono_counter_rsp *rsp =
		(struct sab_cmd_dev_mono_counter_rsp *)rsp_buf;
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);

	if (!op_args) {
		err = SAB_LIB_STATUS(SAB_LIB_RSP_PROC_FAIL);
		return err;
	}

	if (GET_STATUS_CODE(rsp->rsp_code) == SAB_FAILURE_STATUS)
		return err;

	op_args->ele_hsm_fuse_word = rsp->ele_hsm_fuse_word;
	op_args->v2x_hsm_fuse_word = rsp->v2x_hsm_fuse_word;
	op_args->v2x_she_fuse_word = rsp->v2x_she_fuse_word;

	return err;
}
