// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <errno.h>
#include <stdint.h>

#include "sab_storage_close.h"

uint32_t prepare_msg_storage_close(void *phdl,
				  void *cmd_buf, void *rsp_buf,
				  uint32_t *cmd_msg_sz,
				  uint32_t *rsp_msg_sz,
				  uint32_t msg_hdl,
				  void *args)
{
	uint32_t ret = 0;
	struct sab_cmd_storage_close_msg *msg =
		(struct sab_cmd_storage_close_msg *)cmd_buf;

	msg->storage_handle = msg_hdl;

	*cmd_msg_sz = sizeof(struct sab_cmd_storage_close_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_storage_close_rsp);

	return ret;
}

uint32_t proc_msg_rsp_storage_close(void *rsp_buf, void *args)
{
	return SAB_SUCCESS_STATUS;
}
