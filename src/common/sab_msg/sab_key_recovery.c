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

#include "internal/hsm_key_recovery.h"

#include "sab_key_recovery.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_key_recovery(void *phdl,
				 void *cmd_buf, void *rsp_buf,
				 uint32_t *cmd_msg_sz,
				 uint32_t *rsp_msg_sz,
				 uint32_t msg_hdl,
				 void *args)
{
	uint32_t ret = 0;
	struct sab_cmd_pub_key_recovery_msg *cmd =
		(struct sab_cmd_pub_key_recovery_msg *) cmd_buf;
	struct sab_cmd_pub_key_recovery_rsp *rsp =
		(struct sab_cmd_pub_key_recovery_rsp *) rsp_buf;
	op_pub_key_recovery_args_t *op_args = (op_pub_key_recovery_args_t *) args;

	cmd->key_store_handle = msg_hdl;
	cmd->key_identifier = op_args->key_identifier;
	cmd->out_key_addr_ext = 0u;
	cmd->out_key_addr = (uint32_t)plat_os_abs_data_buf(
						(struct plat_os_abs_hdl *)phdl,
						op_args->out_key,
						op_args->out_key_size,
						DATA_BUF_IS_OUTPUT);

	cmd->out_key_size = op_args->out_key_size;
#ifndef PSA_COMPLIANT
	cmd->key_type = op_args->key_type;
	cmd->flags = op_args->flags;
#endif

	*cmd_msg_sz = sizeof(struct sab_cmd_pub_key_recovery_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_pub_key_recovery_rsp);

	cmd->crc = 0u;
	ret |= SAB_MSG_CRC_BIT;

	return ret;
}

uint32_t proc_msg_rsp_key_recovery(void *rsp_buf, void *args)
{
	op_pub_key_recovery_args_t *op_args = (op_pub_key_recovery_args_t *) args;
	struct sab_cmd_pub_key_recovery_rsp *rsp =
		(struct sab_cmd_pub_key_recovery_rsp *) rsp_buf;

#ifdef PSA_COMPLIANT
	op_args->out_key_size = rsp->out_key_size;
#endif

	return SAB_SUCCESS_STATUS;
}
