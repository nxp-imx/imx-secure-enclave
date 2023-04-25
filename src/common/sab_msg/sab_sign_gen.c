// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include "internal/hsm_sign_gen.h"
#include "sab_sign_gen.h"
#include "sab_messaging.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_sign_gen_open(void *phdl,
				   void *cmd_buf, void *rsp_buf,
				   uint32_t *cmd_msg_sz,
				   uint32_t *rsp_msg_sz,
				   uint32_t msg_hdl,
				   void *args)
{
	uint32_t ret = 0;
	struct sab_signature_gen_open_msg *cmd =
		(struct sab_signature_gen_open_msg *) cmd_buf;
#ifndef PSA_COMPLIANT
	open_svc_sign_gen_args_t *op_args = (open_svc_sign_gen_args_t *)args;

	cmd->flags = op_args->flags;
#endif
	*cmd_msg_sz = sizeof(struct sab_signature_gen_open_msg);
	*rsp_msg_sz = sizeof(struct sab_signature_gen_open_rsp);

	cmd->key_store_hdl = msg_hdl;

	return ret;
}

uint32_t proc_msg_rsp_sign_gen_open(void *rsp_buf, void *args)
{
	struct sab_signature_gen_open_rsp *rsp =
				(struct sab_signature_gen_open_rsp *) rsp_buf;
	open_svc_sign_gen_args_t *op_args = (open_svc_sign_gen_args_t *)args;

	op_args->signature_gen_hdl = rsp->sig_gen_hdl;

	return SAB_SUCCESS_STATUS;
}

uint32_t prepare_msg_sign_gen_close(void *phdl,
				    void *cmd_buf, void *rsp_buf,
				    uint32_t *cmd_msg_sz,
				    uint32_t *rsp_msg_sz,
				    uint32_t msg_hdl,
				    void *args)
{
	uint32_t ret = 0;
	struct sab_signature_gen_close_msg *cmd =
		(struct sab_signature_gen_close_msg *) cmd_buf;

	*cmd_msg_sz = sizeof(struct sab_signature_gen_close_msg);
	*rsp_msg_sz = sizeof(struct sab_signature_gen_close_rsp);

	cmd->sig_gen_hdl = msg_hdl;

	return ret;
}

uint32_t proc_msg_rsp_sign_gen_close(void *rsp_buf, void *args)
{
	return SAB_SUCCESS_STATUS;
}

uint32_t prepare_msg_sign_generate(void *phdl,
				   void *cmd_buf, void *rsp_buf,
				   uint32_t *cmd_msg_sz,
				   uint32_t *rsp_msg_sz,
				   uint32_t msg_hdl,
				   void *args)
{
	uint32_t ret = 0;
	struct sab_signature_generate_msg *cmd =
				(struct sab_signature_generate_msg *)cmd_buf;
	op_generate_sign_args_t *op_args = (op_generate_sign_args_t *)args;

	*cmd_msg_sz = sizeof(struct sab_signature_generate_msg);
	*rsp_msg_sz = sizeof(struct sab_signature_generate_rsp);

	cmd->sig_gen_hdl = msg_hdl;
	cmd->key_identifier = op_args->key_identifier;
	set_phy_addr_to_words(&cmd->message_addr,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->message,
						   op_args->message_size,
						   DATA_BUF_IS_INPUT));
	set_phy_addr_to_words(&cmd->signature_addr,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->signature,
						   op_args->signature_size,
						   0u));
	cmd->message_size = op_args->message_size;
	cmd->signature_size = op_args->signature_size;
	cmd->scheme_id = op_args->scheme_id;
	cmd->flags = op_args->flags;
#ifdef PSA_COMPLIANT
	cmd->reserved = 0;
#endif
	cmd->crc = 0u;

	return ret;
}

uint32_t proc_msg_rsp_sign_generate(void *rsp_buf, void *args)
{
	op_generate_sign_args_t *op_args =
			(op_generate_sign_args_t *)args;
	struct sab_signature_generate_rsp *rsp =
			(struct sab_signature_generate_rsp *)rsp_buf;

#ifdef PSA_COMPLIANT
	op_args->exp_signature_size = rsp->signature_size;
#endif

	return SAB_SUCCESS_STATUS;
}
