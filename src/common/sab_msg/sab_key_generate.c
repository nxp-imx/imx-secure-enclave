// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include "internal/hsm_key.h"
#include "internal/hsm_key_generate.h"

#include "sab_key_generate.h"
#include "sab_messaging.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_generatekey(void *phdl,
				 void *cmd_buf, void *rsp_buf,
				 uint32_t *cmd_msg_sz,
				 uint32_t *rsp_msg_sz,
				 uint32_t msg_hdl,
				 void *args)
{
	uint32_t ret = 0;
	struct sab_cmd_generate_key_msg *cmd =
		(struct sab_cmd_generate_key_msg *) cmd_buf;
	op_generate_key_args_t *op_args = (op_generate_key_args_t *) args;

	cmd->key_management_handle = msg_hdl;

	cmd->out_pub_key_sz = op_args->out_size;
	cmd->flags = op_args->flags;
	cmd->key_type = op_args->key_type;
	cmd->key_group = op_args->key_group;
	cmd->key_identifier = *(op_args->key_identifier);
#ifdef CONFIG_PLAT_SECO
	cmd->key_info = op_args->key_info;
#else
	cmd->key_lifetime = op_args->key_lifetime;
	cmd->key_usage = op_args->key_usage;
	cmd->key_sz = op_args->bit_key_sz;
	cmd->permitted_algo = op_args->permitted_algo;
	cmd->key_lifecycle = op_args->key_lifecycle;
#endif
	set_phy_addr_to_words(&cmd->out_key_addr,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->out_key,
						   op_args->out_size,
						   DATA_BUF_IS_OUTPUT));

	*cmd_msg_sz = sizeof(struct sab_cmd_generate_key_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_generate_key_rsp);

	cmd->crc = 0u;

	return ret;
}

uint32_t proc_msg_rsp_generatekey(void *rsp_buf, void *args)
{
	op_generate_key_args_t *op_args = (op_generate_key_args_t *) args;
	struct sab_cmd_generate_key_rsp *rsp =
		(struct sab_cmd_generate_key_rsp *) rsp_buf;

#ifdef CONFIG_PLAT_SECO
	if ((op_args->flags & HSM_OP_KEY_GENERATION_FLAGS_CREATE)
			== HSM_OP_KEY_GENERATION_FLAGS_CREATE)
#endif
		*(op_args->key_identifier) = rsp->key_identifier;
#ifndef CONFIG_PLAT_SECO
		op_args->out_size = rsp->out_key_sz;
#endif
	return SAB_SUCCESS_STATUS;
}
