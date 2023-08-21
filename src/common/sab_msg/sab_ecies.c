// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "internal/hsm_ecies.h"
#include "sab_messaging.h"

#include "sab_ecies.h"

uint32_t prepare_msg_ecies_encryption(void *phdl,
				      void *cmd_buf, void *rsp_buf,
				      uint32_t *cmd_msg_sz,
				      uint32_t *rsp_msg_sz,
				      uint32_t msg_hdl,
				      void *args)
{
	uint32_t ret = SAB_ENGN_PASS;
	struct sab_cmd_ecies_encrypt_msg *cmd =
		(struct sab_cmd_ecies_encrypt_msg *)cmd_buf;
	op_ecies_enc_args_t *op_args =
		(op_ecies_enc_args_t *)args;

	if (!op_args)
		return SAB_ENGN_FAIL;

	cmd->sesssion_handle = msg_hdl;
	cmd->input_addr_ext = 0u;
	set_phy_addr_to_words(&cmd->input_addr,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->input,
						   op_args->input_size,
						   DATA_BUF_IS_INPUT));
	cmd->key_addr_ext = 0u;
	set_phy_addr_to_words(&cmd->key_addr,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->pub_key,
						   op_args->pub_key_size,
						   DATA_BUF_IS_INPUT));
	cmd->p1_addr_ext = 0u;
	set_phy_addr_to_words(&cmd->p1_addr,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->p1,
						   op_args->p1_size,
						   DATA_BUF_IS_INPUT));
	cmd->p2_addr_ext = 0u;
	set_phy_addr_to_words(&cmd->p2_addr,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->p2,
						   op_args->p2_size,
						   DATA_BUF_IS_INPUT));
	cmd->output_addr_ext = 0u;
	set_phy_addr_to_words(&cmd->output_addr,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->output,
						   op_args->out_size,
						   0u));
	cmd->input_size = op_args->input_size;
	cmd->p1_size = op_args->p1_size;
	cmd->p2_size = op_args->p2_size;
	cmd->key_size = op_args->pub_key_size;
	cmd->mac_size = op_args->mac_size;
	cmd->output_size = op_args->out_size;
	cmd->key_type = op_args->key_type;
	cmd->flags = op_args->flags;
	cmd->reserved = 0u;
	cmd->crc = 0u;

	*cmd_msg_sz = sizeof(struct sab_cmd_ecies_encrypt_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_ecies_encrypt_rsp);

	return ret;
}

uint32_t proc_msg_rsp_ecies_encryption(void *rsp_buf, void *args)
{
	struct sab_cmd_ecies_encrypt_rsp *rsp =
		(struct sab_cmd_ecies_encrypt_rsp *)rsp_buf;

	return SAB_SUCCESS_STATUS;
}

uint32_t prepare_msg_ecies_decryption(void *phdl,
				      void *cmd_buf, void *rsp_buf,
				      uint32_t *cmd_msg_sz,
				      uint32_t *rsp_msg_sz,
				      uint32_t msg_hdl,
				      void *args)
{
	uint32_t ret = SAB_ENGN_PASS;
	struct sab_cmd_ecies_decrypt_msg *cmd =
		(struct sab_cmd_ecies_decrypt_msg *)cmd_buf;
	op_ecies_dec_args_t *op_args =
		(op_ecies_dec_args_t *)args;

	if (!op_args)
		return SAB_ENGN_FAIL;

	cmd->cipher_handle = msg_hdl;
	cmd->key_id = op_args->key_identifier;
	set_phy_addr_to_words(&cmd->input_address,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->input,
						   op_args->input_size,
						   DATA_BUF_IS_INPUT));
	set_phy_addr_to_words(&cmd->p1_addr,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->p1,
						   op_args->p1_size,
						   DATA_BUF_IS_INPUT));
	set_phy_addr_to_words(&cmd->p2_addr,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->p2,
						   op_args->p2_size,
						   DATA_BUF_IS_INPUT));
	set_phy_addr_to_words(&cmd->output_address,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->output,
						   op_args->output_size,
						   0u));
	cmd->input_size = op_args->input_size;
	cmd->output_size = op_args->output_size;
	cmd->p1_size = op_args->p1_size;
	cmd->p2_size = op_args->p2_size;
	cmd->mac_size = op_args->mac_size;
	cmd->key_type = op_args->key_type;
	cmd->flags = op_args->flags;
	cmd->crc = 0u;

	*cmd_msg_sz = sizeof(struct sab_cmd_ecies_decrypt_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_ecies_decrypt_rsp);

	return ret;
}

uint32_t proc_msg_rsp_ecies_decryption(void *rsp_buf, void *args)
{
	struct sab_cmd_ecies_decrypt_rsp *rsp =
		(struct sab_cmd_ecies_decrypt_rsp *)rsp_buf;

	return SAB_SUCCESS_STATUS;
}

