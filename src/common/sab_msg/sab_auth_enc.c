// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "internal/hsm_auth_enc.h"
#include "sab_auth_enc.h"
#include "sab_messaging.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_auth_enc(void *phdl,
		void *cmd_buf, void *rsp_buf,
		uint32_t *cmd_msg_sz,
		uint32_t *rsp_msg_sz,
		uint32_t msg_hdl,
		void *args)
{
	uint32_t ret = 0;
	struct sab_cmd_auth_enc_msg *cmd =
		(struct sab_cmd_auth_enc_msg *) cmd_buf;
	op_auth_enc_args_t *op_args =
		(op_auth_enc_args_t *) args;

	cmd->cipher_handle = msg_hdl;
	cmd->key_id = op_args->key_identifier;

	if (op_args->iv_size != 0 && op_args->iv)
		set_phy_addr_to_words(&cmd->iv_address,
				      0u,
				      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
							   op_args->iv,
							   op_args->iv_size,
							   DATA_BUF_IS_INPUT));

	cmd->iv_size = op_args->iv_size;
	cmd->ae_algo = op_args->ae_algo;
	cmd->flags = op_args->flags;
	set_phy_addr_to_words(&cmd->aad_address,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->aad,
						   op_args->aad_size,
						   DATA_BUF_IS_INPUT));

	cmd->aad_size = op_args->aad_size;
	set_phy_addr_to_words(&cmd->input_address,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->input,
						   op_args->input_size,
						   DATA_BUF_IS_INPUT));
	set_phy_addr_to_words(&cmd->output_address,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->output,
						   op_args->output_size,
						   0u));

	cmd->input_length = op_args->input_size;
	cmd->output_length = op_args->output_size;

	*cmd_msg_sz = sizeof(struct sab_cmd_auth_enc_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_auth_enc_rsp);

	return ret;
}

uint32_t proc_msg_rsp_auth_enc(void *rsp_buf, void *args)
{
	op_auth_enc_args_t *op_args =
		(op_auth_enc_args_t *) args;
	struct sab_cmd_auth_enc_rsp *rsp =
		(struct sab_cmd_auth_enc_rsp *) rsp_buf;

#ifdef PSA_COMPLIANT
	op_args->output_size = rsp->output_size;
#endif
	return SAB_SUCCESS_STATUS;
}
