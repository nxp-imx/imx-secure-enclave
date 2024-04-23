// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#include "internal/hsm_gc_cipher.h"

#include "sab_gc_cipher.h"
#include "sab_messaging.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_gc_cipher(void *phdl,
			       void *cmd_buf, void *rsp_buf,
			       uint32_t *cmd_msg_sz,
			       uint32_t *rsp_msg_sz,
			       uint32_t msg_hdl,
			       void *args)
{
	uint32_t ret = SAB_ENGN_PASS;
	struct sab_cmd_gc_cipher_msg *cmd =
			(struct sab_cmd_gc_cipher_msg *)cmd_buf;
	op_gc_cipher_args_t *op_args =
			(op_gc_cipher_args_t *)args;

	if (!op_args)
		return SAB_ENGN_FAIL;

	cmd->algo = op_args->algorithm;
	cmd->mode = op_args->op_mode;
	cmd->data_size = op_args->in_data_buff_sz;
	cmd->key_size = op_args->plain_key_buff_sz;
	cmd->iv_size = op_args->iv_buff_sz;

	set_phy_addr_to_words(&cmd->in_addr,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->in_data_buff,
						   op_args->in_data_buff_sz,
						   DATA_BUF_IS_INPUT));

	set_phy_addr_to_words(&cmd->out_addr,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->out_data_buff,
						   op_args->in_data_buff_sz,
						   DATA_BUF_IS_OUTPUT));

	set_phy_addr_to_words(&cmd->key_addr,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->plain_key_buff,
						   op_args->plain_key_buff_sz,
						   DATA_BUF_IS_INPUT));

	set_phy_addr_to_words(&cmd->iv_addr,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->iv_buff,
						   op_args->iv_buff_sz,
						   DATA_BUF_IS_INPUT));

	*cmd_msg_sz = sizeof(struct sab_cmd_gc_cipher_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_gc_cipher_rsp);

	return ret;
}

uint32_t proc_msg_gc_cipher(void *rsp_buf, void *args)
{
	return SAB_LIB_STATUS(SAB_LIB_SUCCESS);
}
