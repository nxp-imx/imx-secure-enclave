// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "internal/hsm_st_butterfly.h"
#include "sab_messaging.h"

#include "sab_st_butterfly.h"

uint32_t prepare_msg_st_butterfly(void *phdl,
				  void *cmd_buf, void *rsp_buf,
				  uint32_t *cmd_msg_sz,
				  uint32_t *rsp_msg_sz,
				  uint32_t msg_hdl,
				  void *args)
{
	uint32_t ret = SAB_ENGN_PASS;
	struct sab_cmd_st_butterfly_key_exp_msg *cmd =
		(struct sab_cmd_st_butterfly_key_exp_msg *)cmd_buf;
	op_st_butt_key_exp_args_t *op_args =
		(op_st_butt_key_exp_args_t *)args;

	if (!op_args)
		return SAB_ENGN_FAIL;

	cmd->key_management_handle = msg_hdl;
	cmd->key_identifier = op_args->key_identifier;
	cmd->exp_fct_key_identifier = op_args->expansion_fct_key_identifier;
	set_phy_addr_to_words(&cmd->exp_fct_input_address,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->expansion_fct_input,
						   op_args->expansion_fct_input_size,
						   DATA_BUF_IS_INPUT));
	set_phy_addr_to_words(&cmd->hash_value_address,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->hash_value,
						   op_args->hash_value_size,
						   DATA_BUF_IS_INPUT));
	set_phy_addr_to_words(&cmd->pr_reconst_value_address,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->pr_reconstruction_value,
						   op_args->pr_reconstruction_value_size,
						   DATA_BUF_IS_INPUT));
	cmd->exp_fct_input_size = op_args->expansion_fct_input_size;
	cmd->hash_value_size = op_args->hash_value_size;
	cmd->pr_reconst_value_size = op_args->pr_reconstruction_value_size;
	cmd->flags = op_args->flags;
	cmd->dest_key_identifier = *op_args->dest_key_identifier;
	set_phy_addr_to_words(&cmd->output_address,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->output,
						   op_args->output_size,
						   0u));
	cmd->output_size = op_args->output_size;
	cmd->key_type = op_args->key_type;
	cmd->exp_fct_algorithm = op_args->expansion_fct_algo;
	cmd->key_group = op_args->key_group;
	cmd->key_info = op_args->key_info;
	cmd->crc = 0u;

	*cmd_msg_sz = sizeof(struct sab_cmd_st_butterfly_key_exp_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_st_butterfly_key_exp_rsp);

	return ret;
}

uint32_t proc_msg_rsp_st_butterfly(void *rsp_buf, void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);
	op_st_butt_key_exp_args_t *op_args = (op_st_butt_key_exp_args_t *)args;
	struct sab_cmd_st_butterfly_key_exp_rsp *rsp =
		(struct sab_cmd_st_butterfly_key_exp_rsp *)rsp_buf;

	if (!op_args) {
		err = SAB_LIB_STATUS(SAB_LIB_RSP_PROC_FAIL);
		goto exit;
	}

	if ((op_args->flags & HSM_OP_ST_BUTTERFLY_KEY_FLAGS_CREATE)
			== HSM_OP_ST_BUTTERFLY_KEY_FLAGS_CREATE) {
		*op_args->dest_key_identifier = rsp->dest_key_identifier;
	}
exit:
	return err;
}
