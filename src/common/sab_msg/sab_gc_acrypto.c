/*
 * Copyright 2023 NXP
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

#include "internal/hsm_gc_acrypto.h"

#include "sab_gc_acrypto.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_gc_acrypto(void *phdl,
				void *cmd_buf, void *rsp_buf,
				uint32_t *cmd_msg_sz,
				uint32_t *rsp_msg_sz,
				uint32_t msg_hdl,
				void *args)
{
	uint32_t ret = 0;
	struct sab_cmd_gc_acrypto_msg *cmd =
			(struct sab_cmd_gc_acrypto_msg *)cmd_buf;
	op_gc_acrypto_args_t *op_args =
			(op_gc_acrypto_args_t *)args;
	uint64_t plat_addr;

	cmd->buffers_addr_msb = 0u;
	cmd->algorithm = op_args->algorithm;
	cmd->op_mode = op_args->op_mode;
	cmd->key_size = op_args->bit_key_sz;

	if (cmd->op_mode == HSM_GC_ACRYPTO_OP_MODE_DECRYPT)
		plat_addr = plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						 op_args->data_buff1,
						 op_args->data_buff1_size,
						 DATA_BUF_IS_OUTPUT);
	else
		plat_addr = plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						 op_args->data_buff1,
						 op_args->data_buff1_size,
						 DATA_BUF_IS_INPUT);
	if (plat_addr <= UINT32_MAX)
		cmd->data_buff1_addr = (uint32_t)plat_addr;

	if (cmd->op_mode == HSM_GC_ACRYPTO_OP_MODE_DECRYPT ||
	    cmd->op_mode == HSM_GC_ACRYPTO_OP_MODE_SIGN_VER)
		plat_addr = plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						 op_args->data_buff2,
						 op_args->data_buff2_size,
						 DATA_BUF_IS_INPUT);
	else
		plat_addr = plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						 op_args->data_buff2,
						 op_args->data_buff2_size,
						 DATA_BUF_IS_OUTPUT);
	if (plat_addr <= UINT32_MAX)
		cmd->data_buff2_addr = (uint32_t)plat_addr;

	plat_addr = plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
					 op_args->key_buff1,
					 op_args->key_buff1_size,
					 DATA_BUF_IS_INPUT);
	if (plat_addr <= UINT32_MAX)
		cmd->key_buff1_addr = (uint32_t)plat_addr;

	plat_addr = plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
					 op_args->key_buff2,
					 op_args->key_buff2_size,
					 DATA_BUF_IS_INPUT);
	if (plat_addr <= UINT32_MAX)
		cmd->key_buff2_addr = (uint32_t)plat_addr;

	cmd->data_buff1_size = op_args->data_buff1_size;
	cmd->data_buff2_size = op_args->data_buff2_size;
	cmd->key_buff1_size = op_args->key_buff1_size;
	cmd->key_buff2_size = op_args->key_buff2_size;

	plat_addr = plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
					 op_args->rsa_label,
					 op_args->rsa_label_size,
					 DATA_BUF_IS_INPUT);
	if (plat_addr <= UINT32_MAX)
		cmd->rsa_label_addr = (uint32_t)plat_addr;

	cmd->rsa_label_size = op_args->rsa_label_size;
	cmd->rsa_salt_len = op_args->rsa_salt_len;

	*cmd_msg_sz = sizeof(struct sab_cmd_gc_acrypto_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_gc_acrypto_rsp);

	return ret;
}

uint32_t proc_msg_gc_acrypto(void *rsp_buf, void *args)
{
	struct sab_cmd_gc_acrypto_rsp *rsp =
			(struct sab_cmd_gc_acrypto_rsp *)rsp_buf;
	op_gc_acrypto_args_t *op_args =
			(op_gc_acrypto_args_t *)args;

	op_args->exp_plaintext_len = rsp->plaintext_len;
	op_args->verification_status = rsp->verification_status;

	return SAB_SUCCESS_STATUS;
}
