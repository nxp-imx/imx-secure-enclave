// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "internal/hsm_butterfly.h"
#include "sab_messaging.h"
#include "plat_utils.h"

#include "sab_butterfly.h"

uint32_t prepare_msg_butterfly(void *phdl,
			       void *cmd_buf, void *rsp_buf,
			       uint32_t *cmd_msg_sz,
			       uint32_t *rsp_msg_sz,
			       uint32_t msg_hdl,
			       void *args)
{
	uint32_t ret;
	struct sab_cmd_butterfly_key_exp_msg *cmd =
		(struct sab_cmd_butterfly_key_exp_msg *)cmd_buf;
	op_butt_key_exp_args_t *op_args =
		(op_butt_key_exp_args_t *)args;
	uint64_t phy_addr = 0;
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_CMD_MSG_PREP_FAIL);

	if (!op_args)
		return SAB_LIB_STATUS(SAB_LIB_CMD_MSG_PREP_FAIL);

	cmd->key_management_handle = msg_hdl;
	cmd->key_identifier = op_args->key_identifier;

	ret = plat_os_abs_data_buf_v2((struct plat_os_abs_hdl *)phdl,
				      &phy_addr,
				      op_args->expansion_function_value,
				      op_args->expansion_function_value_size,
				      DATA_BUF_IS_INPUT);
	if (ret != PLAT_SUCCESS) {
		err |= ret;
		goto exit;
	}

	set_phy_addr_to_words(&cmd->expansion_function_value_addr,
			      0u,
			      phy_addr);

	ret = plat_os_abs_data_buf_v2((struct plat_os_abs_hdl *)phdl,
				      &phy_addr,
				      op_args->hash_value,
				      op_args->hash_value_size,
				      DATA_BUF_IS_INPUT);
	if (ret != PLAT_SUCCESS) {
		err |= ret;
		goto exit;
	}

	set_phy_addr_to_words(&cmd->hash_value_addr,
			      0u,
			      phy_addr);

	ret = plat_os_abs_data_buf_v2((struct plat_os_abs_hdl *)phdl,
				      &phy_addr,
				      op_args->pr_reconstruction_value,
				      op_args->pr_reconstruction_value_size,
				      DATA_BUF_IS_INPUT);
	if (ret != PLAT_SUCCESS) {
		err |= ret;
		goto exit;
	}

	set_phy_addr_to_words(&cmd->pr_reconstruction_value_addr,
			      0u,
			      phy_addr);

	cmd->expansion_function_value_size = op_args->expansion_function_value_size;
	cmd->hash_value_size = op_args->hash_value_size;
	cmd->pr_reconstruction_value_size = op_args->pr_reconstruction_value_size;
	cmd->flags = op_args->flags;
	cmd->dest_key_identifier = *op_args->dest_key_identifier;

	ret = plat_os_abs_data_buf_v2((struct plat_os_abs_hdl *)phdl,
				      &phy_addr,
				      op_args->output,
				      op_args->output_size,
				      0u);
	if (ret != PLAT_SUCCESS) {
		err |= ret;
		goto exit;
	}

	set_phy_addr_to_words(&cmd->output_address,
			      0u,
			      phy_addr);

	cmd->output_size = op_args->output_size;
	cmd->key_type = op_args->key_type;
	cmd->rsv = 0u;
	cmd->key_group = op_args->key_group;
	cmd->key_info = op_args->key_info;
	cmd->crc = 0u;

	*cmd_msg_sz = sizeof(struct sab_cmd_butterfly_key_exp_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_butterfly_key_exp_rsp);

	err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);
exit:
	return err;
}

uint32_t proc_msg_rsp_butterfly(void *rsp_buf, void *args)
{
	op_butt_key_exp_args_t *op_args = (op_butt_key_exp_args_t *)args;
	struct sab_cmd_butterfly_key_exp_rsp *rsp =
		(struct sab_cmd_butterfly_key_exp_rsp *)rsp_buf;

	if (!op_args)
		return SAB_LIB_STATUS(SAB_LIB_RSP_PROC_FAIL);

	if ((op_args->flags & HSM_OP_BUTTERFLY_KEY_FLAGS_CREATE)
			== HSM_OP_BUTTERFLY_KEY_FLAGS_CREATE) {
		*op_args->dest_key_identifier = rsp->dest_key_identifier;
	}

	return SAB_LIB_STATUS(SAB_LIB_SUCCESS);
}
