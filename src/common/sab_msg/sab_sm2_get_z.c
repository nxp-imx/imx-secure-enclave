// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "internal/hsm_sm2_get_z.h"
#include "sab_sm2_get_z.h"
#include "sab_messaging.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_sm2_get_z(void *phdl,
			       void *cmd_buf, void *rsp_buf,
			       uint32_t *cmd_msg_sz,
			       uint32_t *rsp_msg_sz,
			       uint32_t msg_hdl,
			       void *args)
{
	uint32_t ret = SAB_ENGN_PASS;
	struct sab_cmd_sm2_get_z_msg *cmd =
		(struct sab_cmd_sm2_get_z_msg *)cmd_buf;
	op_sm2_get_z_args_t *op_args =	(op_sm2_get_z_args_t *)args;

	if (!op_args)
		return SAB_ENGN_FAIL;

	cmd->session_handle = msg_hdl;
	cmd->input_address_ext = 0u;
	set_phy_addr_to_words(&cmd->public_key_address,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->public_key,
						   op_args->public_key_size,
						   DATA_BUF_IS_INPUT));
	set_phy_addr_to_words(&cmd->id_address,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->identifier,
						   op_args->id_size,
						   DATA_BUF_IS_INPUT));
	cmd->output_address_ext = 0U;
	set_phy_addr_to_words(&cmd->z_value_address,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->z_value,
						   op_args->z_size,
						   0u));
	cmd->public_key_size = op_args->public_key_size;
	cmd->id_size = op_args->id_size;
	cmd->z_size = op_args->z_size;
	cmd->key_type = op_args->key_type;
	cmd->flags = op_args->flags;
	cmd->reserved = 0u;
	cmd->crc = 0u;

	*cmd_msg_sz = sizeof(struct sab_cmd_sm2_get_z_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_sm2_get_z_rsp);

	return ret;
}

uint32_t proc_msg_rsp_sm2_get_z(void *rsp_buf, void *args)
{
	op_sm2_get_z_args_t *op_args =
		(op_sm2_get_z_args_t *)args;
	struct sab_cmd_sm2_get_z_rsp *rsp =
		(struct sab_cmd_sm2_get_z_rsp *)rsp_buf;

	return SAB_SUCCESS_STATUS;
}
