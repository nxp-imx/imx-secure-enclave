// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include "internal/crrm_get_nonce.h"

#include "sab_get_nonce.h"
#include "sab_messaging.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_get_nonce(void *phdl,
			       void *cmd_buf, void *rsp_buf,
			       uint32_t *cmd_msg_sz,
			       uint32_t *rsp_msg_sz,
			       uint32_t msg_hdl,
			       void *args)
{
	uint32_t ret;
	uint64_t temp;
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_CMD_MSG_PREP_FAIL);
	struct sab_cmd_get_nonce_msg *cmd =
		(struct sab_cmd_get_nonce_msg *)cmd_buf;
	op_get_nonce_args_t *op_args = (op_get_nonce_args_t *)args;

	if (!op_args)
		return err;

	cmd->timer_id = op_args->timer_id;
	cmd->input_size = op_args->nonce_size;
	ret = plat_os_abs_data_buf_v2((struct plat_os_abs_hdl *)phdl,
				      &temp,
				      op_args->nonce_addr,
				      cmd->input_size,
				      DATA_BUF_IS_OUTPUT);
	if (ret != PLAT_SUCCESS) {
		err |= ret;
		return err;
	}

	set_phy_addr_to_words(&cmd->addr, 0u, temp);

	*cmd_msg_sz = sizeof(struct sab_cmd_get_nonce_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_get_nonce_rsp);

	err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);

	return err;
}

uint32_t proc_msg_rsp_get_nonce(void *rsp_buf, void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);
	op_get_nonce_args_t *op_args = (op_get_nonce_args_t *)args;
	struct sab_cmd_get_nonce_rsp *rsp =
		(struct sab_cmd_get_nonce_rsp *)rsp_buf;

	if (!op_args) {
		err = SAB_LIB_STATUS(SAB_LIB_RSP_PROC_FAIL);
		return err;
	}

	op_args->output_size = rsp->output_size;

	return err;
}
