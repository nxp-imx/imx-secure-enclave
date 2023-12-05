// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "internal/hsm_sm2_eces.h"
#include "sab_messaging.h"

#include "sab_sm2_eces.h"

uint32_t prepare_msg_sm2_eces_open_req(void *phdl,
				       void *cmd_buf, void *rsp_buf,
				       uint32_t *cmd_msg_sz,
				       uint32_t *rsp_msg_sz,
				       uint32_t msg_hdl,
				       void *args)
{
	uint32_t ret = SAB_ENGN_PASS;
	struct sab_cmd_sm2_eces_dec_open_msg *cmd =
		(struct sab_cmd_sm2_eces_dec_open_msg *)cmd_buf;
	open_svc_sm2_eces_args_t *op_args =
		(open_svc_sm2_eces_args_t *)args;

	if (!op_args)
		return SAB_ENGN_FAIL;

	cmd->input_address_ext = 0;
	cmd->output_address_ext = 0;
	cmd->key_store_handle = msg_hdl;
	cmd->flags = op_args->flags;
	cmd->rsv[0] = 0u;
	cmd->rsv[1] = 0u;
	cmd->rsv[2] = 0u;
	cmd->crc = 0u;

	*cmd_msg_sz = sizeof(struct sab_cmd_sm2_eces_dec_open_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_sm2_eces_dec_open_rsp);

	return ret;
}

uint32_t proc_msg_rsp_sm2_eces_open_req(void *rsp_buf, void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);
	struct sab_cmd_sm2_eces_dec_open_rsp *rsp =
		(struct sab_cmd_sm2_eces_dec_open_rsp *)rsp_buf;
	open_svc_sm2_eces_args_t *op_args =
		(open_svc_sm2_eces_args_t *)args;

	if (!op_args) {
		err = SAB_LIB_STATUS(SAB_LIB_RSP_PROC_FAIL);
		goto exit;
	}

	op_args->sm2_eces_hdl = rsp->sm2_eces_handle;
exit:
	return err;
}

uint32_t prepare_msg_sm2_eces_close_req(void *phdl,
					void *cmd_buf, void *rsp_buf,
					uint32_t *cmd_msg_sz,
					uint32_t *rsp_msg_sz,
					uint32_t msg_hdl,
					void *args)
{
	uint32_t ret = SAB_ENGN_PASS;
	struct sab_cmd_sm2_eces_dec_close_msg *cmd =
		(struct sab_cmd_sm2_eces_dec_close_msg *)cmd_buf;

	cmd->sm2_eces_handle = msg_hdl;

	*cmd_msg_sz = sizeof(struct sab_cmd_sm2_eces_dec_close_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_sm2_eces_dec_close_rsp);

	return ret;
}

uint32_t proc_msg_rsp_sm2_eces_close_req(void *rsp_buf, void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);
	struct sab_cmd_sm2_eces_dec_close_rsp *rsp =
		(struct sab_cmd_sm2_eces_dec_close_rsp *)rsp_buf;

	return err;
}

uint32_t prepare_msg_sm2_eces_encryption(void *phdl,
					 void *cmd_buf, void *rsp_buf,
					 uint32_t *cmd_msg_sz,
					 uint32_t *rsp_msg_sz,
					 uint32_t msg_hdl,
					 void *args)
{
	uint32_t ret = SAB_ENGN_PASS;
	struct sab_cmd_sm2_eces_enc_msg *cmd =
		(struct sab_cmd_sm2_eces_enc_msg *)cmd_buf;
	op_sm2_eces_enc_args_t *op_args =
		(op_sm2_eces_enc_args_t *)args;

	if (!op_args)
		return SAB_ENGN_FAIL;

	cmd->session_handle = msg_hdl;
	cmd->input_addr_ext = 0u;
	set_phy_addr_to_words(&cmd->input_addr,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->input,
						   op_args->input_size,
						   DATA_BUF_IS_INPUT));
	cmd->key_addr_ext = 0U;
	set_phy_addr_to_words(&cmd->key_addr,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->pub_key,
						   op_args->pub_key_size,
						   DATA_BUF_IS_INPUT));

	cmd->output_addr_ext = 0U;
	set_phy_addr_to_words(&cmd->output_addr,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->output,
						   op_args->output_size,
						   0u));

	cmd->input_size = op_args->input_size;
	cmd->output_size = op_args->output_size;
	cmd->key_size = op_args->pub_key_size;
	cmd->key_type = op_args->key_type;
	cmd->flags = op_args->flags;
	cmd->crc = 0u;

	*cmd_msg_sz = sizeof(struct sab_cmd_sm2_eces_enc_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_sm2_eces_enc_rsp);

	return ret;
}

uint32_t proc_msg_rsp_sm2_eces_encryption(void *rsp_buf, void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);
	struct sab_cmd_sm2_eces_enc_rsp *rsp =
		(struct sab_cmd_sm2_eces_enc_rsp *)rsp_buf;

	return err;
}

uint32_t prepare_msg_sm2_eces_decryption(void *phdl,
					 void *cmd_buf, void *rsp_buf,
					 uint32_t *cmd_msg_sz,
					 uint32_t *rsp_msg_sz,
					 uint32_t msg_hdl,
					 void *args)
{
	uint32_t ret = SAB_ENGN_PASS;
	struct sab_cmd_sm2_eces_dec_msg *cmd =
		(struct sab_cmd_sm2_eces_dec_msg *)cmd_buf;
	op_sm2_eces_dec_args_t *op_args =
		(op_sm2_eces_dec_args_t *)args;

	if (!op_args)
		return SAB_ENGN_FAIL;

	cmd->sm2_eces_handle = msg_hdl;
	cmd->key_id = op_args->key_identifier;

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

	cmd->input_size = op_args->input_size;
	cmd->output_size = op_args->output_size;
	cmd->key_type = op_args->key_type;
	cmd->flags = op_args->flags;
	cmd->rsv = 0;
	cmd->crc = 0u;

	*cmd_msg_sz = sizeof(struct sab_cmd_sm2_eces_dec_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_sm2_eces_dec_rsp);

	return ret;
}

uint32_t proc_msg_rsp_sm2_eces_decryption(void *rsp_buf, void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);
	struct sab_cmd_sm2_eces_dec_rsp *rsp =
		(struct sab_cmd_sm2_eces_dec_rsp *)rsp_buf;

	return err;
}
