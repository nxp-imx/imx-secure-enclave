// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "sab_messaging.h"
#include "sab_load_plain_key.h"
#include "internal/she_load_plain_key.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_load_plain_key(void *phdl,
				    void *cmd_buf,
				    void *rsp_buf,
				    uint32_t *cmd_msg_sz,
				    uint32_t *rsp_msg_sz,
				    uint32_t msg_hdl,
				    void *args)
{
	uint32_t ret = SAB_ENGN_PASS;
	struct sab_she_load_plain_key_msg *cmd =
		(struct sab_she_load_plain_key_msg *)cmd_buf;

	op_load_plain_key_args_t *op_args = (op_load_plain_key_args_t *)args;

	cmd->utils_handle = msg_hdl;

	plat_os_abs_memcpy(cmd->key, op_args->key, SHE_KEY_SIZE_IN_BYTES);

	*cmd_msg_sz = sizeof(struct sab_she_load_plain_key_msg);
	*rsp_msg_sz = sizeof(struct sab_she_load_plain_key_rsp);

	return ret;
}

uint32_t proc_msg_rsp_load_plain_key(void *rsp_buf, void *args)
{
	struct sab_she_load_plain_key_rsp *rsp =
		(struct sab_she_load_plain_key_rsp *)rsp_buf;

	if (rsp->rsp_code != SAB_SUCCESS_STATUS)
		return rsp->rsp_code;

	return SAB_SUCCESS_STATUS;
}
