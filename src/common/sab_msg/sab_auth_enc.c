// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
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
	uint32_t ret = SAB_ENGN_PASS;
	struct sab_cmd_auth_enc_msg *cmd =
		(struct sab_cmd_auth_enc_msg *) cmd_buf;
	op_auth_enc_args_t *op_args =
		(op_auth_enc_args_t *) args;

	if (!op_args)
		return SAB_ENGN_FAIL;

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
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);
	op_auth_enc_args_t *op_args =
		(op_auth_enc_args_t *) args;
	struct sab_cmd_auth_enc_rsp *rsp =
		(struct sab_cmd_auth_enc_rsp *) rsp_buf;

#ifdef PSA_COMPLIANT
	if (!op_args) {
		err = SAB_LIB_STATUS(SAB_LIB_RSP_PROC_FAIL);
		goto exit;
	}

	op_args->exp_output_size = rsp->output_size;
exit:
#endif
	return err;
}

#ifdef PSA_COMPLIANT
uint32_t prepare_msg_auth_enc_new(void *phdl,
				  void *cmd_buf, void *rsp_buf,
				  uint32_t *cmd_msg_sz,
				  uint32_t *rsp_msg_sz,
				  uint32_t msg_hdl,
				  void *args)
{
	uint32_t ret = SAB_ENGN_PASS;
	struct sab_cmd_auth_enc_new_msg *cmd = (struct sab_cmd_auth_enc_new_msg *)cmd_buf;
	op_auth_enc_new_args_t *op_args = (op_auth_enc_new_args_t *)args;

	if (!op_args)
		return SAB_ENGN_FAIL;

	cmd->cipher_handle = msg_hdl;
	cmd->algo = op_args->ae_algo;
	cmd->flags = op_args->flags;
	cmd->key_type = op_args->key_type;
	cmd->key_size = op_args->key_size;
	if (op_args->flags & HSM_AUTH_ENC_FLAGS_PLAINTEXT_KEY)
		set_phy_addr_to_words(&cmd->key,
				      0u,
				      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
							   op_args->key,
							   op_args->key_size,
							   DATA_BUF_IS_INPUT));
	else
		cmd->key = op_args->key_id;

	cmd->iv_size = op_args->iv_size;
	set_phy_addr_to_words(&cmd->iv_address_in,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->iv_in,
						   op_args->iv_size,
						   DATA_BUF_IS_INPUT));

	if (op_args->flags & HSM_AUTH_ENC_FLAGS_GENERATE_FULL_IV  ||
	    op_args->flags & HSM_AUTH_ENC_FLAGS_GENERATE_COUNTER_IV) {
		op_args->iv_out = plat_os_abs_malloc(SAB_AUTH_ENC_IV_OUT_SIZE);

		if (!op_args->iv_out)
			return SAB_ENGN_FAIL;

		set_phy_addr_to_words(&cmd->iv_address_out,
				      0u,
				      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
							   op_args->iv_out,
							   SAB_AUTH_ENC_IV_OUT_SIZE,
							   DATA_BUF_IS_OUTPUT));
	}

	cmd->tag_size = op_args->tag_size;
	set_phy_addr_to_words(&cmd->tag_address,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->tag,
						   op_args->tag_size,
						   DATA_BUF_IS_IN_OUT));

	cmd->aad_size = op_args->aad_size;
	set_phy_addr_to_words(&cmd->aad_address,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->aad,
						   op_args->aad_size,
						   DATA_BUF_IS_INPUT));
	cmd->input_size = op_args->input_size;
	set_phy_addr_to_words(&cmd->input_address,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->input,
						   op_args->input_size,
						   DATA_BUF_IS_INPUT));
	cmd->output_size = op_args->output_size;
	set_phy_addr_to_words(&cmd->output_address,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->output,
						   op_args->output_size,
						   DATA_BUF_IS_OUTPUT));

	cmd->context_size = op_args->context_size;
	set_phy_addr_to_words(&cmd->context_address,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->context,
						   op_args->context_size,
						   DATA_BUF_IS_IN_OUT));

	*cmd_msg_sz = sizeof(struct sab_cmd_auth_enc_new_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_auth_enc_new_rsp);

	return ret;
}

uint32_t proc_msg_rsp_auth_enc_new(void *rsp_buf, void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);
	op_auth_enc_new_args_t *op_args = (op_auth_enc_new_args_t *)args;
	struct sab_cmd_auth_enc_new_rsp *rsp = (struct sab_cmd_auth_enc_new_rsp *)rsp_buf;

	if (!op_args) {
		err = SAB_LIB_STATUS(SAB_LIB_RSP_PROC_FAIL);
		goto exit;
	}

	op_args->verify_status = rsp->verify_status;
	op_args->exp_output_size = rsp->output_size;
exit:
	return err;
}
#endif
