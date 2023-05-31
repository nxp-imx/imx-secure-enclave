// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "internal/hsm_get_key_attr.h"

#include "sab_get_key_attr.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_get_key_attr(void *phdl,
				  void *cmd_buf, void *rsp_buf,
				  uint32_t *cmd_msg_sz,
				  uint32_t *rsp_msg_sz,
				  uint32_t msg_hdl,
				  void *args)
{
	uint32_t ret = SAB_ENGN_PASS;
	struct sab_cmd_get_key_attr_msg *cmd =
		(struct sab_cmd_get_key_attr_msg *) cmd_buf;
	op_get_key_attr_args_t *op_args = (op_get_key_attr_args_t *) args;

	if (!op_args)
		return SAB_ENGN_FAIL;

	cmd->key_management_hdl = msg_hdl;
	cmd->key_identifier = op_args->key_identifier;

	*cmd_msg_sz = sizeof(struct sab_cmd_get_key_attr_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_get_key_attr_rsp);

	return ret;
}

uint32_t proc_msg_rsp_get_key_attr(void *rsp_buf, void *args)
{
	op_get_key_attr_args_t *op_args = (op_get_key_attr_args_t *) args;
	struct sab_cmd_get_key_attr_rsp *rsp =
		(struct sab_cmd_get_key_attr_rsp *) rsp_buf;

	if (!op_args)
		return SAB_FAILURE_STATUS;

	op_args->key_type = rsp->type;
	op_args->bit_key_sz = rsp->size_bits;
	op_args->key_lifetime = rsp->lifetime;
	op_args->key_usage = rsp->usage;
	op_args->permitted_algo = rsp->algo;
	op_args->lifecycle = rsp->lifecycle;
	return SAB_SUCCESS_STATUS;
}
