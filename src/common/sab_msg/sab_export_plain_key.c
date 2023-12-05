// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "sab_messaging.h"
#include "sab_export_plain_key.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_export_plain_key(void *phdl,
				      void *cmd_buf,
				      void *rsp_buf,
				      uint32_t *cmd_msg_sz,
				      uint32_t *rsp_msg_sz,
				      uint32_t msg_hdl,
				      void *args)
{
	uint32_t ret = SAB_ENGN_PASS;
	struct sab_she_export_plain_key_msg *cmd =
		(struct sab_she_export_plain_key_msg *)cmd_buf;

	cmd->utils_handle = msg_hdl;

	*cmd_msg_sz = sizeof(struct sab_she_export_plain_key_msg);
	*rsp_msg_sz = sizeof(struct sab_she_export_plain_key_rsp);

	return ret;
}

uint32_t proc_msg_rsp_export_plain_key(void *rsp_buf, void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);
	op_export_plain_key_args_t *op_args =
		(op_export_plain_key_args_t *)args;
	struct sab_she_export_plain_key_rsp *rsp =
		(struct sab_she_export_plain_key_rsp *)rsp_buf;


	if (!op_args) {
		err = SAB_LIB_STATUS(SAB_LIB_RSP_PROC_FAIL);
		goto exit;
	}

	if (GET_STATUS_CODE(rsp->rsp_code) == SAB_FAILURE_STATUS)
		goto exit;

	plat_os_abs_memcpy(op_args->m1, (uint8_t *)rsp->m1, op_args->m1_size);
	plat_os_abs_memcpy(op_args->m2, (uint8_t *)rsp->m2, op_args->m2_size);
	plat_os_abs_memcpy(op_args->m3, (uint8_t *)rsp->m3, op_args->m3_size);
	plat_os_abs_memcpy(op_args->m4, (uint8_t *)rsp->m4, op_args->m4_size);
	plat_os_abs_memcpy(op_args->m5, (uint8_t *)rsp->m5, op_args->m5_size);

exit:
	return err;
}
