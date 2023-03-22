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

#include "internal/hsm_importkey.h"

#include "sab_import_key.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_importkey(void *phdl,
			       void *cmd_buf, void *rsp_buf,
			       uint32_t *cmd_msg_sz,
			       uint32_t *rsp_msg_sz,
			       uint32_t msg_hdl,
			       void *args)
{
	uint32_t ret = 0;
	struct sab_cmd_import_key_msg *cmd =
		(struct sab_cmd_import_key_msg *) cmd_buf;
	struct sab_cmd_import_key_rsp *rsp =
		(struct sab_cmd_import_key_rsp *) rsp_buf;
	op_import_key_args_t *op_args = (op_import_key_args_t *) args;

	cmd->key_management_hdl = msg_hdl;
	cmd->flags = op_args->flags;

	cmd->input_lsb_addr = plat_os_abs_data_buf(phdl,
						   op_args->input_lsb_addr,
						   op_args->input_size,
						   DATA_BUF_IS_INPUT);
	cmd->input_size = op_args->input_size;

	if ((op_args->flags & HSM_OP_IMPORT_KEY_INPUT_E2GO_TLV)
			== HSM_OP_IMPORT_KEY_INPUT_SIGNED_MSG) {
		cmd->sign_msg.key_blob_lsb = plat_os_abs_data_buf(phdl,
								  op_args->key_blob,
								  op_args->key_blob_sz,
								  DATA_BUF_IS_INPUT);
		cmd->sign_msg.key_blob_size = op_args->key_blob_sz;
		cmd->sign_msg.iv_lsb = plat_os_abs_data_buf(phdl,
							    op_args->iv,
							    op_args->iv_sz,
							    DATA_BUF_IS_INPUT);
		cmd->sign_msg.iv_size = op_args->iv_sz;
		cmd->sign_msg.key_group = op_args->key_group;
		cmd->sign_msg.key_id = op_args->key_id;
	}
	*cmd_msg_sz = sizeof(struct sab_cmd_import_key_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_import_key_rsp);

	cmd->crc = 0u;

	return ret;
}

uint32_t proc_msg_rsp_importkey(void *rsp_buf, void *args)
{
	op_import_key_args_t *op_args = (op_import_key_args_t *) args;
	struct sab_cmd_import_key_rsp *rsp =
		(struct sab_cmd_import_key_rsp *) rsp_buf;

	op_args->key_identifier = rsp->key_identifier;

	return SAB_SUCCESS_STATUS;
}
