// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include "internal/crrm_refresh_AWDT.h"

#include "sab_refresh_AWDT.h"
#include "sab_messaging.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_refresh_AWDT(void *phdl,
				  void *cmd_buf, void *rsp_buf,
				  uint32_t *cmd_msg_sz,
				  uint32_t *rsp_msg_sz,
				  uint32_t msg_hdl,
				  void *args)
{
	uint32_t ret;
	uint64_t temp;
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_CMD_MSG_PREP_FAIL);
	struct sab_cmd_refresh_AWDT_msg *cmd =
		(struct sab_cmd_refresh_AWDT_msg *)cmd_buf;
	op_refresh_AWDT_args_t *op_args = (op_refresh_AWDT_args_t *)args;

	if (!op_args)
		return err;

	cmd->timer_id = op_args->timer_id;
	cmd->pub_key_index = op_args->pub_key_index;
	cmd->req_data_size = op_args->req_data_size;
	ret = plat_os_abs_data_buf_v2((struct plat_os_abs_hdl *)phdl,
				      &temp,
				      op_args->req_data_addr,
				      cmd->req_data_size,
				      DATA_BUF_IS_INPUT);
	if (ret != PLAT_SUCCESS) {
		err |= ret;
		return err;
	}

	set_phy_addr_to_words(&cmd->req_data_addr, 0u, temp);

	*cmd_msg_sz = sizeof(struct sab_cmd_refresh_AWDT_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_refresh_AWDT_rsp);

	err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);

	return err;
}

uint32_t proc_msg_rsp_refresh_AWDT(void *rsp_buf, void *args)
{
	return SAB_LIB_STATUS(SAB_LIB_SUCCESS);
}
