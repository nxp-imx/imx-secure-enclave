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
	cmd->key_id = *op_args->key_identifier;
	cmd->in_priv_key_sz = op_args->encryted_prv_key_sz;
	cmd->key_group = op_args->key_group;
	cmd->flags = op_args->flags;
	cmd->key_lifetime = op_args->key_lifetime;
	cmd->key_usage = op_args->key_usage;
	cmd->key_type = op_args->key_type;
	cmd->bit_key_sz = op_args->bit_key_sz;
	cmd->permitted_algo = op_args->permitted_algo;

	if ((op_args->flags & HSM_OP_IMPORT_KEY_FLAGS_WRP_PRV_WRPK)
			== HSM_OP_IMPORT_KEY_FLAGS_WRP_PRV_WRPK) {
		/* For a key wrapped with provisioned wrap key,
		 * attributes (lifetime, usage, type, size, permitted algorithm)
		 * must not be set in the command message.
		 */
		cmd->key_lifetime = 0;
		cmd->key_usage = 0;
		cmd->key_type = 0;
		cmd->bit_key_sz = 0;
		cmd->permitted_algo = 0;
	}
	cmd->priv_key_in_lsb_addr = (uint32_t)plat_os_abs_data_buf(
						(struct plat_os_abs_hdl *)phdl,
						op_args->encryted_prv_key,
						cmd->in_priv_key_sz,
						DATA_BUF_IS_INPUT);

	*cmd_msg_sz = sizeof(struct sab_cmd_import_key_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_import_key_rsp);

	cmd->crc = 0u;
	ret |= SAB_MSG_CRC_BIT;

	return ret;
}

uint32_t proc_msg_rsp_importkey(void *rsp_buf, void *args)
{
	op_import_key_args_t *op_args = (op_import_key_args_t *) args;
	struct sab_cmd_import_key_rsp *rsp =
		(struct sab_cmd_import_key_rsp *) rsp_buf;

	*(op_args->key_identifier) = rsp->key_identifier;

	return SAB_SUCCESS_STATUS;
}
