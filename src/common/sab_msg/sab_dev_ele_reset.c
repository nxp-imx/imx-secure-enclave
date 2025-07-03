// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <stdio.h>

#include "sab_dev_ele_reset.h"
#include "sab_messaging.h"

uint32_t prepare_msg_dev_ele_reset(void *phdl, void *cmd_buf, void *rsp_buf,
				   uint32_t *cmd_msg_sz, uint32_t *rsp_msg_sz,
				   uint32_t msg_hdl, void *args)
{
	struct sab_cmd_dev_ele_reset_msg *cmd =
		(struct sab_cmd_dev_ele_reset_msg *)cmd_buf;

	*cmd_msg_sz = sizeof(struct sab_cmd_dev_ele_reset_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_dev_ele_reset_rsp);

	return SAB_LIB_STATUS(SAB_LIB_SUCCESS);
}

uint32_t proc_msg_rsp_dev_ele_reset(void *rsp_buf, void *args)
{
	struct sab_cmd_dev_ele_reset_rsp *rsp =
		(struct sab_cmd_dev_ele_reset_rsp *)rsp_buf;

	return SAB_LIB_STATUS(SAB_LIB_SUCCESS);
}
