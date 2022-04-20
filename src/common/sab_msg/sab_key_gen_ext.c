/*
 * Copyright 2022 NXP
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

#include "internal/hsm_key.h"
#include "internal/hsm_key_gen_ext.h"

#include "sab_key_gen_ext.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t proc_msg_rsp_gen_key_ext(void *rsp_buf, void *args)
{
	op_generate_key_ext_args_t *op_args = (op_generate_key_ext_args_t *) args;
	struct sab_cmd_generate_key_ext_rsp *rsp =
		(struct sab_cmd_generate_key_ext_rsp *) rsp_buf;

	if ((op_args->flags & HSM_OP_KEY_GENERATION_FLAGS_CREATE)
			== HSM_OP_KEY_GENERATION_FLAGS_CREATE) {
		*(op_args->key_identifier) = rsp->key_identifier;
	}

	return SAB_SUCCESS_STATUS;
}

uint32_t prepare_msg_gen_key_ext(void *phdl,
				 void *cmd_buf, void *rsp_buf,
				 uint32_t *cmd_msg_sz,
				 uint32_t *rsp_msg_sz,
				 uint32_t msg_hdl,
				 void *args)
{
	uint32_t ret = 0;
	struct sab_cmd_generate_key_ext_msg *cmd =
		(struct sab_cmd_generate_key_ext_msg *) cmd_buf;
	struct sab_cmd_generate_key_rsp *rsp =
		(struct sab_cmd_generate_key_rsp *) rsp_buf;
	op_generate_key_ext_args_t *op_args = (op_generate_key_ext_args_t *) args;

	cmd->key_management_handle = msg_hdl;
	cmd->key_identifier = *(op_args->key_identifier);
	cmd->out_key_sz = op_args->out_size;
	cmd->flags = op_args->flags;
	cmd->key_type = op_args->key_type;
	cmd->key_group = op_args->key_group;
	cmd->key_info = op_args->key_info;
	cmd->out_key_addr = (uint32_t)plat_os_abs_data_buf(
						(struct plat_os_abs_hdl *)phdl,
						op_args->out_key,
						op_args->out_size,
						DATA_BUF_IS_OUTPUT);

	*cmd_msg_sz = sizeof(struct sab_cmd_generate_key_ext_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_generate_key_ext_rsp);

	cmd->min_mac_len = op_args->min_mac_len;
	cmd->reserved[0] = op_args->reserved[0];
	cmd->reserved[1] = op_args->reserved[1];
	cmd->reserved[2] = op_args->reserved[2];
	cmd->crc = 0u;
	ret |= SAB_MSG_CRC_BIT;

	return ret;
}
