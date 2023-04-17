// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include <string.h>

#include "internal/hsm_verify_sign.h"

#include "sab_verify_sign.h"
#include "sab_messaging.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_verify_sign_open(void *phdl,
				      void *cmd_buf, void *rsp_buf,
				      uint32_t *cmd_msg_sz,
				      uint32_t *rsp_msg_sz,
				      uint32_t msg_hdl,
				      void *args)
{
	uint32_t ret = 0;
	struct sab_signature_verify_open_msg *cmd =
			(struct sab_signature_verify_open_msg *)cmd_buf;
#ifndef PSA_COMPLIANT
	open_svc_sign_ver_args_t *op_args = (open_svc_sign_ver_args_t *)args;

	cmd->flags = op_args->flags;
#endif
	cmd->session_handle = msg_hdl;

	*cmd_msg_sz = sizeof(struct sab_signature_verify_open_msg);
	*rsp_msg_sz = sizeof(struct sab_signature_verify_open_rsp);

	return ret;
}

uint32_t proc_msg_rsp_verify_sign_open(void *rsp_buf, void *args)
{
	struct sab_signature_verify_open_rsp *rsp =
			(struct sab_signature_verify_open_rsp *)rsp_buf;
	open_svc_sign_ver_args_t *op_args = (open_svc_sign_ver_args_t *)args;

	op_args->sig_ver_hdl = rsp->sig_ver_hdl;

	return SAB_SUCCESS_STATUS;
}

uint32_t prepare_msg_verify_sign_close(void *phdl,
				       void *cmd_buf, void *rsp_buf,
				       uint32_t *cmd_msg_sz,
				       uint32_t *rsp_msg_sz,
				       uint32_t msg_hdl,
				       void *args)
{
	uint32_t ret = 0;
	struct sab_signature_verify_close_msg *cmd =
			(struct sab_signature_verify_close_msg *)cmd_buf;

	cmd->sig_ver_hdl = msg_hdl;

	*cmd_msg_sz = sizeof(struct sab_signature_verify_close_msg);
	*rsp_msg_sz = sizeof(struct sab_signature_verify_close_rsp);

	return ret;
}

uint32_t proc_msg_rsp_verify_sign_close(void *rsp_buf, void *args)
{
	return SAB_SUCCESS_STATUS;
}

uint32_t prepare_msg_verify_sign(void *phdl,
				 void *cmd_buf, void *rsp_buf,
				 uint32_t *cmd_msg_sz,
				 uint32_t *rsp_msg_sz,
				 uint32_t msg_hdl,
				 void *args)
{
	uint32_t ret = 0;
	struct sab_signature_verify_msg *cmd =
			(struct sab_signature_verify_msg *)cmd_buf;
	op_verify_sign_args_t *op_args = (op_verify_sign_args_t *)args;

	cmd->sig_ver_hdl = msg_hdl;
	set_phy_addr_to_words(&cmd->key_addr,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->key,
						   op_args->key_size,
						   DATA_BUF_IS_INPUT));
	set_phy_addr_to_words(&cmd->msg_addr,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->message,
						   op_args->message_size,
						   DATA_BUF_IS_INPUT));
	set_phy_addr_to_words(&cmd->sig_addr,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->signature,
						   op_args->signature_size,
						   DATA_BUF_IS_INPUT));
	cmd->key_size = op_args->key_size;
	cmd->sig_size = op_args->signature_size;
	cmd->message_size = op_args->message_size;
	cmd->sig_scheme = op_args->scheme_id;
#ifdef PSA_COMPLIANT
	cmd->key_security_size = op_args->key_sz;
	cmd->key_type = op_args->pkey_type;
#endif
	cmd->flags = op_args->flags;
	memset(cmd->reserved, 0, SAB_CMD_VERIFY_SIGN_RESERVED);
	cmd->crc = 0u;

	*cmd_msg_sz = sizeof(struct sab_signature_verify_msg);
	*rsp_msg_sz = sizeof(struct sab_signature_verify_rsp);

	return ret;
}

uint32_t proc_msg_rsp_verify_sign(void *rsp_buf, void *args)
{
	struct sab_signature_verify_rsp *rsp =
			(struct sab_signature_verify_rsp *)rsp_buf;
	op_verify_sign_args_t *op_args = (op_verify_sign_args_t *)args;

	op_args->verification_status = rsp->verification_status;

	return SAB_SUCCESS_STATUS;
}
