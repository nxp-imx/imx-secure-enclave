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

#include "internal/hsm_hash.h"

#include "sab_hash.h"
#include "sab_messaging.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

#define CTX_ADDR_IGNORE 0xF1

uint32_t prepare_msg_hash_one_go(void *phdl,
				 void *cmd_buf, void *rsp_buf,
				 uint32_t *cmd_msg_sz,
				 uint32_t *rsp_msg_sz,
				 uint32_t msg_hdl,
				 void *args)
{
	uint32_t ret = 0;
	struct sab_hash_one_go_msg *cmd =
		(struct sab_hash_one_go_msg *) cmd_buf;
	struct sab_hash_one_go_rsp *rsp =
		(struct sab_hash_one_go_rsp *) rsp_buf;
	op_hash_one_go_args_t *op_args = (op_hash_one_go_args_t *) args;

#ifdef PSA_COMPLIANT
	/*
	 * ctx_addr: context address.
	 * Context is ignored in case of one shot operation flag = Bit 1
	 * Bit 4-6 reserved and get context size operation flag = Bit 8.
	 */
	if (!(op_args->svc_flags & CTX_ADDR_IGNORE)) {
		set_phy_addr_to_words(&cmd->ctx_addr,
				      0u,
				      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
							   op_args->ctx,
							   op_args->ctx_size,
							   DATA_BUF_IS_IN_OUT));
	}
	cmd->ctx_size = op_args->ctx_size;
#else
	cmd->hash_hdl = msg_hdl;
#endif
	set_phy_addr_to_words(&cmd->input_addr,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->input,
						   op_args->input_size,
						   DATA_BUF_IS_INPUT));
	set_phy_addr_to_words(&cmd->output_addr,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->output,
						   op_args->output_size,
						   DATA_BUF_IS_OUTPUT));
	cmd->input_size = op_args->input_size;
	cmd->output_size = op_args->output_size;
	cmd->algo = op_args->algo;
	cmd->flags = op_args->svc_flags;

	memset(cmd->reserved, 0, SAB_HASH_RESERVED_BYTES);

	*cmd_msg_sz = sizeof(struct sab_hash_one_go_msg);
	*rsp_msg_sz = sizeof(struct sab_hash_one_go_rsp);

	cmd->crc = 0u;

	return ret;
}

uint32_t proc_msg_rsp_hash_one_go(void *rsp_buf, void *args)
{
	op_hash_one_go_args_t *op_args = (op_hash_one_go_args_t *) args;
	struct sab_hash_one_go_rsp *rsp =
		(struct sab_hash_one_go_rsp *) rsp_buf;
#ifdef PSA_COMPLIANT
	op_args->exp_output_size = rsp->output_size;
	op_args->context_size = rsp->context_size;
#endif

	return SAB_SUCCESS_STATUS;
}

#ifndef PSA_COMPLIANT
uint32_t prepare_msg_hash_open_req(void *phdl,
				   void *cmd_buf, void *rsp_buf,
				   uint32_t *cmd_msg_sz,
				   uint32_t *rsp_msg_sz,
				   uint32_t msg_hdl,
				   void *args)
{
	uint32_t ret = 0;
	struct sab_hash_open_msg *cmd =
		(struct sab_hash_open_msg *) cmd_buf;
	open_svc_hash_args_t *op_args = (open_svc_hash_args_t *) args;

	cmd->session_handle = msg_hdl;
	cmd->input_address_ext = 0u;
	cmd->output_address_ext = 0u;
	/*
	 * flags: User input through op args is reserved, as per ELE FW spec.
	 */
	cmd->flags = 0u;
	cmd->reserved[0] = 0u;
	cmd->reserved[1] = 0u;
	cmd->reserved[2] = 0u;

	*cmd_msg_sz = sizeof(struct sab_hash_open_msg);
	*rsp_msg_sz = sizeof(struct sab_hash_open_rsp);

	cmd->crc = 0u;

	return ret;
}

uint32_t proc_msg_rsp_hash_open_req(void *rsp_buf, void *args)
{
	struct sab_hash_open_rsp *rsp =
		(struct sab_hash_open_rsp *) rsp_buf;
	open_svc_hash_args_t *op_args = (open_svc_hash_args_t *) args;

	op_args->hash_hdl = rsp->hash_hdl;

	return SAB_SUCCESS_STATUS;
}

uint32_t prepare_msg_hash_close_req(void *phdl,
				    void *cmd_buf, void *rsp_buf,
				    uint32_t *cmd_msg_sz,
				    uint32_t *rsp_msg_sz,
				    uint32_t msg_hdl,
				    void *args)
{
	uint32_t ret = 0;
	struct sab_hash_close_msg *cmd = (struct sab_hash_close_msg *) cmd_buf;

	*cmd_msg_sz = sizeof(struct sab_hash_close_msg);
	*rsp_msg_sz = sizeof(struct sab_hash_close_rsp);

	cmd->hash_hdl = msg_hdl;

	return ret;
}

uint32_t proc_msg_rsp_hash_close_req(void *rsp_buf, void *args)
{
	return SAB_SUCCESS_STATUS;
}
#endif
