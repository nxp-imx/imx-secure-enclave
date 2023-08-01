// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "sab_messaging.h"
#include "sab_key_update.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_key_update(void *phdl,
				void *cmd_buf, void *rsp_buf,
				uint32_t *cmd_msg_sz,
				uint32_t *rsp_msg_sz,
				uint32_t msg_hdl,
				void *args)
{
	uint32_t ret = SAB_ENGN_PASS;
	struct sab_she_key_update_msg *cmd =
		(struct sab_she_key_update_msg *)cmd_buf;

	op_key_update_args_t *op_args = (op_key_update_args_t *)args;

	cmd->utils_handle = msg_hdl;
	cmd->key_id = op_args->key_ext | op_args->key_id;

	plat_os_abs_memcpy((uint8_t *)cmd->m1, op_args->m1, op_args->m1_size);
	plat_os_abs_memcpy((uint8_t *)cmd->m2, op_args->m2, op_args->m2_size);
	plat_os_abs_memcpy((uint8_t *)cmd->m3, op_args->m3, op_args->m3_size);

	*cmd_msg_sz = sizeof(struct sab_she_key_update_msg);
	*rsp_msg_sz = sizeof(struct sab_she_key_update_rsp);

	return ret;
}

uint32_t proc_msg_rsp_key_update(void *rsp_buf, void *args)
{
	op_key_update_args_t *op_args =
		(op_key_update_args_t *)args;
	struct sab_she_key_update_rsp *rsp =
		(struct sab_she_key_update_rsp *)rsp_buf;

	if (!op_args)
		return SAB_FAILURE_STATUS;

	if (rsp->rsp_code != SAB_SUCCESS_STATUS)
		return rsp->rsp_code;

	plat_os_abs_memcpy(op_args->m4, (uint8_t *)rsp->m4, op_args->m4_size);
	plat_os_abs_memcpy(op_args->m5, (uint8_t *)rsp->m5, op_args->m5_size);

	return SAB_SUCCESS_STATUS;
}
