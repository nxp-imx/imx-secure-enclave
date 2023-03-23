/*
 * Copyright 2022-2023 NXP
 *
 * NXP Confidential.
 * This software is owned or controlled by NXP and may only be used strictly
 * in accordance with the applicable license terms.  By expressly accepting
 * such terms or by downloading, installing, activating and/or otherwise using
 * the software, you are agreeing that you have read, and that you agree to
 * comply with and are bound by, such license terms.  If you do not agree to be
 * bound by the applicable license terms, then you may not retain, install,
 * activate or otherwise use the software.
 */

#include <string.h>

#include "internal/hsm_cipher.h"

#include "sab_cipher.h"
#include "sab_messaging.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_cipher_one_go(void *phdl,
				   void *cmd_buf, void *rsp_buf,
				   uint32_t *cmd_msg_sz,
				   uint32_t *rsp_msg_sz,
				   uint32_t msg_hdl,
				   void *args)
{
	int32_t ret = 0;
	struct sab_cmd_cipher_one_go_msg *cmd =
		(struct sab_cmd_cipher_one_go_msg *) cmd_buf;
	struct sab_cmd_cipher_one_go_rsp *rsp =
		(struct sab_cmd_cipher_one_go_rsp *) rsp_buf;
	op_cipher_one_go_args_t *op_args = (op_cipher_one_go_args_t *) args;

	cmd->cipher_handle = msg_hdl;
	cmd->key_id = op_args->key_identifier;
	if (op_args->iv == NULL) {
		cmd->iv_address = 0u;
	} else {
		set_phy_addr_to_words(&cmd->iv_address,
				      0u,
				      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
							   op_args->iv,
							   op_args->iv_size,
							   DATA_BUF_IS_INPUT));
	}
	cmd->iv_size = op_args->iv_size;
	cmd->algo = op_args->cipher_algo;
	cmd->flags = op_args->flags;
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
						   DATA_BUF_IS_OUTPUT));
	cmd->input_size = op_args->input_size;
	cmd->output_size = op_args->output_size;
	cmd->crc = 0u;

	*cmd_msg_sz = sizeof(struct sab_cmd_cipher_one_go_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_cipher_one_go_rsp);

	return ret;
}

uint32_t proc_msg_rsp_cipher_one_go(void *rsp_buf, void *args)
{
	op_cipher_one_go_args_t *op_args = (op_cipher_one_go_args_t *) args;
	struct sab_cmd_cipher_one_go_rsp *rsp =
		(struct sab_cmd_cipher_one_go_rsp *) rsp_buf;

#ifdef PSA_COMPLIANT
	op_args->output_size = rsp->output_size;
#endif

	return SAB_SUCCESS_STATUS;
}

uint32_t prepare_msg_cipher_open_req(void *phdl,
				     void *cmd_buf, void *rsp_buf,
				     uint32_t *cmd_msg_sz,
				     uint32_t *rsp_msg_sz,
				     uint32_t msg_hdl,
				     void *args)
{
	uint32_t ret = 0;
	struct sab_cmd_cipher_open_msg *cmd =
		(struct sab_cmd_cipher_open_msg *) cmd_buf;
	struct sab_cmd_cipher_open_rsp *rsp =
		(struct sab_cmd_cipher_open_rsp *) rsp_buf;
	open_svc_cipher_args_t *op_args = (open_svc_cipher_args_t *) args;

	cmd->input_address_ext = 0;
	cmd->output_address_ext = 0;
	cmd->flags = op_args->flags;
	cmd->key_store_handle = msg_hdl;

	cmd->crc = 0u;

	*cmd_msg_sz = sizeof(struct sab_cmd_cipher_open_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_cipher_open_rsp);

	return ret;
}

uint32_t proc_msg_rsp_cipher_open_req(void *rsp_buf, void *args)
{
	struct sab_cmd_cipher_open_rsp *rsp =
		(struct sab_cmd_cipher_open_rsp *) rsp_buf;
	open_svc_cipher_args_t *op_args = (open_svc_cipher_args_t *) args;

	op_args->cipher_hdl = rsp->cipher_handle;

	return SAB_SUCCESS_STATUS;
}

uint32_t prepare_msg_cipher_close_req(void *phdl,
				      void *cmd_buf, void *rsp_buf,
				      uint32_t *cmd_msg_sz,
				      uint32_t *rsp_msg_sz,
				      uint32_t msg_hdl,
				      void *args)
{
	uint32_t ret = 0;
	struct sab_cmd_cipher_close_msg *cmd =
		(struct sab_cmd_cipher_close_msg *) cmd_buf;
	struct sab_cmd_cipher_close_rsp *rsp =
		(struct sab_cmd_cipher_close_rsp *) rsp_buf;

	*cmd_msg_sz = sizeof(struct sab_cmd_cipher_close_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_cipher_close_rsp);

	cmd->cipher_handle = msg_hdl;

	return ret;
}

uint32_t proc_msg_rsp_cipher_close_req(void *rsp_buf, void *args)
{
	return SAB_SUCCESS_STATUS;
}
