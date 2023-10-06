// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "sab_get_id.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_get_id(void *phdl, void *cmd_buf, void *rsp_buf,
			    uint32_t *cmd_msg_sz, uint32_t *rsp_msg_sz,
			    uint32_t msg_hdl, void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_CMD_MSG_PREP_FAIL);
	uint32_t ret;
	op_get_id_args_t *op_args = (op_get_id_args_t *)args;
	struct sab_cmd_get_id_msg *cmd =
		(struct sab_cmd_get_id_msg *)cmd_buf;

	cmd->she_utils_handle = msg_hdl;
	ret = plat_os_abs_memcpy_v2(cmd->challenge,
				    op_args->challenge,
				    SHE_CHALLENGE_SIZE);
	if (ret != PLAT_SUCCESS) {
		err |= ret;
		return err;
	}

	*cmd_msg_sz = sizeof(struct sab_cmd_get_id_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_get_id_rsp);

	err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);

	return err;
}

uint32_t proc_msg_rsp_get_id(void *rsp_buf, void *args)
{
	op_get_id_args_t *op_args = (op_get_id_args_t *)args;
	struct sab_cmd_get_id_rsp *rsp =
		(struct sab_cmd_get_id_rsp *)rsp_buf;
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_RSP_PROC_FAIL);
	uint32_t ret;

	if (!op_args)
		return err;

	if (rsp->rsp_code != SAB_SUCCESS_STATUS) {
		err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);
		return err;
	}

	ret = plat_os_abs_memcpy_v2(op_args->mac, rsp->mac, SHE_MAC_SIZE);
	if (ret != PLAT_SUCCESS) {
		err |= ret;
		return err;
	}

	ret = plat_os_abs_memcpy_v2(op_args->id, rsp->id, SHE_ID_SIZE);
	if (ret != PLAT_SUCCESS) {
		err |= ret;
		return err;
	}

	op_args->sreg = rsp->sreg;

	err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);
	return err;
}
