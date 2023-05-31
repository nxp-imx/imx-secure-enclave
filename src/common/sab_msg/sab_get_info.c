// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "internal/hsm_get_info.h"

#include "sab_get_info.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_get_info(void *phdl, void *cmd_buf, void *rsp_buf,
			      uint32_t *cmd_msg_sz, uint32_t *rsp_msg_sz,
			      uint32_t msg_hdl, void *args)
{
	uint32_t ret = SAB_ENGN_PASS;
	struct sab_cmd_get_info_msg *cmd =
		(struct sab_cmd_get_info_msg *) cmd_buf;

	cmd->session_handle = msg_hdl;

	*cmd_msg_sz = sizeof(struct sab_cmd_get_info_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_get_info_rsp);

	return ret;
}

uint32_t proc_msg_rsp_get_info(void *rsp_buf, void *args)
{
	op_get_info_args_t *op_args = (op_get_info_args_t *) args;
	struct sab_cmd_get_info_rsp *rsp =
		(struct sab_cmd_get_info_rsp *) rsp_buf;
	uint32_t ret = SAB_SUCCESS_STATUS;

	if (!op_args)
		return SAB_FAILURE_STATUS;

	if (rsp->rsp_code != SAB_SUCCESS_STATUS)
		goto exit;

	op_args->user_sab_id = rsp->user_sab_id;
	op_args->chip_unq_id_sz = CHIP_UNIQUE_ID_SZ;
	op_args->chip_unique_id = plat_os_abs_malloc(CHIP_UNIQUE_ID_SZ);
	if (op_args->chip_unique_id == NULL) {
		goto exit;
	}

	plat_os_abs_memcpy(op_args->chip_unique_id,
			   rsp->uid,
			   CHIP_UNIQUE_ID_SZ);
	op_args->chip_monotonic_counter = rsp->monotonic_counter;
	op_args->chip_life_cycle = rsp->lifecycle;
	op_args->version = rsp->version;
	op_args->version_ext = rsp->version_ext;
	op_args->fips_mode = rsp->fips_mode;
exit:
	return ret;
}
