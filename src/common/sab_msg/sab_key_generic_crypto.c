// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "internal/hsm_key_generic_crypto.h"
#include "sab_messaging.h"
#include "sab_key_generic_crypto.h"

uint32_t prepare_msg_key_generic_crypto_open(void *phdl,
					     void *cmd_buf, void *rsp_buf,
					     uint32_t *cmd_msg_sz,
					     uint32_t *rsp_msg_sz,
					     uint32_t msg_hdl,
					     void *args)
{
	uint32_t ret = SAB_ENGN_PASS;
	struct sab_key_generic_crypto_srv_open_msg *cmd =
		(struct sab_key_generic_crypto_srv_open_msg *)cmd_buf;
	open_svc_key_generic_crypto_args_t *op_args =
		(open_svc_key_generic_crypto_args_t *)args;

	if (!op_args)
		return SAB_ENGN_FAIL;

	cmd->session_handle = msg_hdl;
	cmd->input_address_ext = 0u;
	cmd->output_address_ext = 0u;
	cmd->flags = op_args->flags;
	cmd->rsv[0] = 0u;
	cmd->rsv[1] = 0u;
	cmd->rsv[2] = 0u;
	cmd->crc = 0u;

	*cmd_msg_sz = sizeof(struct sab_key_generic_crypto_srv_open_msg);
	*rsp_msg_sz = sizeof(struct sab_key_generic_crypto_srv_open_rsp);

	return ret;
}

uint32_t proc_msg_rsp_key_generic_crypto_open(void *rsp_buf, void *args)
{
	struct sab_key_generic_crypto_srv_open_rsp *rsp =
		(struct sab_key_generic_crypto_srv_open_rsp *)rsp_buf;
	open_svc_key_generic_crypto_args_t *op_args =
		(open_svc_key_generic_crypto_args_t *)args;

	if (!op_args)
		return SAB_FAILURE_STATUS;

	op_args->key_generic_crypto_hdl = rsp->key_generic_crypto_srv_handle;

	return SAB_SUCCESS_STATUS;
}

uint32_t prepare_msg_key_generic_crypto_close(void *phdl,
					      void *cmd_buf, void *rsp_buf,
					      uint32_t *cmd_msg_sz,
					      uint32_t *rsp_msg_sz,
					      uint32_t msg_hdl,
					      void *args)
{
	uint32_t ret = SAB_ENGN_PASS;
	struct sab_key_generic_crypto_srv_close_msg *cmd =
		(struct sab_key_generic_crypto_srv_close_msg *)cmd_buf;

	cmd->key_generic_crypto_srv_handle = msg_hdl;

	*cmd_msg_sz = sizeof(struct sab_key_generic_crypto_srv_close_msg);
	*rsp_msg_sz = sizeof(struct sab_key_generic_crypto_srv_close_rsp);

	return ret;
}

uint32_t proc_msg_rsp_key_generic_crypto_close(void *rsp_buf, void *args)
{
	struct sab_key_generic_crypto_srv_close_rsp *rsp =
		(struct sab_key_generic_crypto_srv_close_rsp *)rsp_buf;

	return SAB_SUCCESS_STATUS;
}

uint32_t prepare_msg_key_generic_crypto(void *phdl,
					void *cmd_buf, void *rsp_buf,
					uint32_t *cmd_msg_sz,
					uint32_t *rsp_msg_sz,
					uint32_t msg_hdl,
					void *args)
{
	uint32_t ret = SAB_ENGN_PASS;
	struct sab_key_generic_crypto_srv_msg *cmd =
		(struct sab_key_generic_crypto_srv_msg *)cmd_buf;
	op_key_generic_crypto_args_t *op_args =
		(op_key_generic_crypto_args_t *)args;

	if (!op_args)
		return SAB_ENGN_FAIL;

	cmd->key_generic_crypto_srv_handle = msg_hdl;
	cmd->key_size = op_args->key_size;
	set_phy_addr_to_words(&cmd->key_address,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->key,
						   op_args->key_size,
						   DATA_BUF_IS_INPUT));
	if (op_args->iv_size != 0) {
		set_phy_addr_to_words(&cmd->iv_address,
				      0u,
				      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
							   op_args->iv,
							   op_args->iv_size,
							   DATA_BUF_IS_INPUT));
	} else {
		cmd->iv_address = 0;
	}

	cmd->iv_size = op_args->iv_size;
	set_phy_addr_to_words(&cmd->aad_address,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->aad,
						   op_args->aad_size,
						   DATA_BUF_IS_INPUT));
	cmd->aad_size = op_args->aad_size;
	cmd->rsv = 0;
	cmd->crypto_algo = op_args->crypto_algo;
	cmd->flags = op_args->flags;
	cmd->tag_size = op_args->tag_size;
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
	cmd->crc = 0u;

	*cmd_msg_sz = sizeof(struct sab_key_generic_crypto_srv_msg);
	*rsp_msg_sz = sizeof(struct sab_key_generic_crypto_srv_rsp);

	return ret;
}

uint32_t proc_msg_rsp_key_generic_crypto(void *rsp_buf, void *args)
{
	struct sab_key_generic_crypto_srv_rsp *rsp =
		(struct sab_key_generic_crypto_srv_rsp *)rsp_buf;

	return SAB_SUCCESS_STATUS;
}
