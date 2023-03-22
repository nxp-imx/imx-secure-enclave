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

#include "internal/hsm_gc_akey_gen.h"

#include "sab_gc_akey_gen.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_gc_akey_gen(void *phdl,
				 void *cmd_buf, void *rsp_buf,
				 uint32_t *cmd_msg_sz,
				 uint32_t *rsp_msg_sz,
				 uint32_t msg_hdl,
				 void *args)
{
	uint32_t ret = 0;
	struct sab_cmd_gc_akey_gen_msg *cmd =
			(struct sab_cmd_gc_akey_gen_msg *)cmd_buf;
	op_gc_akey_gen_args_t *op_args =
			(op_gc_akey_gen_args_t *)args;
	uint64_t plat_addr;

	cmd->buffers_addr_msb = 0u;

	plat_addr = plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
					 op_args->modulus,
					 op_args->modulus_size,
					 DATA_BUF_IS_OUTPUT);
	if (plat_addr <= UINT32_MAX)
		cmd->modulus_addr = (uint32_t)plat_addr;

	plat_addr = plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
					 op_args->priv_buff,
					 op_args->priv_buff_size,
					 DATA_BUF_IS_OUTPUT);
	if (plat_addr <= UINT32_MAX)
		cmd->priv_buff_addr = (uint32_t)plat_addr;

	plat_addr = plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
					 op_args->pub_buff,
					 op_args->pub_buff_size,
					 DATA_BUF_IS_INPUT);
	if (plat_addr <= UINT32_MAX)
		cmd->pub_buff_addr = (uint32_t)plat_addr;

	cmd->modulus_size = op_args->modulus_size;
	cmd->priv_buff_size = op_args->priv_buff_size;
	cmd->pub_buff_size = op_args->pub_buff_size;
	cmd->key_type = op_args->key_type;
	cmd->key_size_bits = op_args->bit_key_sz;

	*cmd_msg_sz = sizeof(struct sab_cmd_gc_akey_gen_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_gc_akey_gen_rsp);

	return ret;
}

uint32_t proc_msg_gc_akey_gen(void *rsp_buf, void *args)
{
	return SAB_SUCCESS_STATUS;
}
