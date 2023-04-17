// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <errno.h>
#include <stdint.h>

#include "sab_storage_open.h"
#include "sab_nvm.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_storage_open(void *phdl,
				  void *cmd_buf, void *rsp_buf,
				  uint32_t *cmd_msg_sz,
				  uint32_t *rsp_msg_sz,
				  uint32_t msg_hdl,
				  void *args)
{
	uint32_t ret = 0;
	struct sab_cmd_storage_open_msg *msg =
		(struct sab_cmd_storage_open_msg *)cmd_buf;
	op_storage_open_args_t *op_args = (op_storage_open_args_t *) args;

	msg->session_handle = msg_hdl;
	msg->flags = op_args->flags;

	*cmd_msg_sz = sizeof(struct sab_cmd_storage_open_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_storage_open_rsp);

	return ret;
}

uint32_t proc_msg_rsp_storage_open(void *rsp_buf, void *args)
{
	struct sab_cmd_storage_open_rsp *rsp =
		(struct sab_cmd_storage_open_rsp *)rsp_buf;
	op_storage_open_args_t *op_args =
		(op_storage_open_args_t *)args;

	op_args->storage_handle = rsp->storage_handle;

	return SAB_SUCCESS_STATUS;
}
