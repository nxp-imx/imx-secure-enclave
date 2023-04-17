// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "internal/hsm_gc_acrypto.h"

#include "sab_gc_acrypto.h"
#include "sab_messaging.h"

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

	cmd->buffers_addr_msb = 0u;
	cmd->algorithm = op_args->algorithm;
	cmd->op_mode = op_args->op_mode;
	cmd->key_size = op_args->bit_key_sz;

	if (cmd->op_mode == HSM_GC_ACRYPTO_OP_MODE_DECRYPT)
		set_phy_addr_to_words(&cmd->data_buff1_addr,
				      0u,
				      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
							   op_args->data_buff1,
							   op_args->data_buff1_size,
							   DATA_BUF_IS_OUTPUT));
	else
		set_phy_addr_to_words(&cmd->data_buff1_addr,
				      0u,
				      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
							   op_args->data_buff1,
							   op_args->data_buff1_size,
							   DATA_BUF_IS_INPUT));

	if (cmd->op_mode == HSM_GC_ACRYPTO_OP_MODE_DECRYPT ||
	    cmd->op_mode == HSM_GC_ACRYPTO_OP_MODE_SIGN_VER)
		set_phy_addr_to_words(&cmd->data_buff2_addr,
				      0u,
				      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
							   op_args->data_buff2,
							   op_args->data_buff2_size,
							   DATA_BUF_IS_INPUT));
	else
		set_phy_addr_to_words(&cmd->data_buff2_addr,
				      0u,
				      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
							   op_args->data_buff2,
							   op_args->data_buff2_size,
							   DATA_BUF_IS_OUTPUT));

	set_phy_addr_to_words(&cmd->key_buff1_addr,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->key_buff1,
						   op_args->key_buff1_size,
						   DATA_BUF_IS_INPUT));

	set_phy_addr_to_words(&cmd->key_buff2_addr,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->key_buff2,
						   op_args->key_buff2_size,
						   DATA_BUF_IS_INPUT));

	cmd->data_buff1_size = op_args->data_buff1_size;
	cmd->data_buff2_size = op_args->data_buff2_size;
	cmd->key_buff1_size = op_args->key_buff1_size;
	cmd->key_buff2_size = op_args->key_buff2_size;

	set_phy_addr_to_words(&cmd->rsa_label_addr,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->rsa_label,
						   op_args->rsa_label_size,
						   DATA_BUF_IS_INPUT));

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
