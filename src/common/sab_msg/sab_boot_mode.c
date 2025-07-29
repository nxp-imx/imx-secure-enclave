// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include "internal/crrm_boot_mode.h"

#include "sab_boot_mode.h"
#include "sab_messaging.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_get_boot_mode(void *phdl,
				   void *cmd_buf, void *rsp_buf,
				   uint32_t *cmd_msg_sz,
				   uint32_t *rsp_msg_sz,
				   uint32_t msg_hdl,
				   void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);

	*cmd_msg_sz = sizeof(struct sab_cmd_get_boot_mode_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_get_boot_mode_rsp);

	return err;
}

uint32_t proc_msg_rsp_get_boot_mode(void *rsp_buf, void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);
	op_get_boot_mode_args_t *op_args = (op_get_boot_mode_args_t *)args;
	struct sab_cmd_get_boot_mode_rsp *rsp =
		(struct sab_cmd_get_boot_mode_rsp *)rsp_buf;

	if (!op_args) {
		err = SAB_LIB_STATUS(SAB_LIB_RSP_PROC_FAIL);
		return err;
	}

	op_args->boot_mode = rsp->boot_mode;
	op_args->timer_id = rsp->timer_id;

	return err;
}

uint32_t prepare_msg_set_boot_mode(void *phdl,
				   void *cmd_buf, void *rsp_buf,
				   uint32_t *cmd_msg_sz,
				   uint32_t *rsp_msg_sz,
				   uint32_t msg_hdl,
				   void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);
	struct sab_cmd_set_boot_mode_msg *cmd =
		(struct sab_cmd_set_boot_mode_msg *)cmd_buf;
	op_set_boot_mode_args_t *op_args = (op_set_boot_mode_args_t *)args;

	if (!op_args) {
		err = SAB_LIB_STATUS(SAB_LIB_RSP_PROC_FAIL);
		return err;
	}

	cmd->new_boot_mode = op_args->new_boot_mode;

	*cmd_msg_sz = sizeof(struct sab_cmd_set_boot_mode_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_set_boot_mode_rsp);

	return err;
}

uint32_t proc_msg_rsp_set_boot_mode(void *rsp_buf, void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);
	op_set_boot_mode_args_t *op_args = (op_set_boot_mode_args_t *)args;
	struct sab_cmd_set_boot_mode_rsp *rsp =
		(struct sab_cmd_set_boot_mode_rsp *)rsp_buf;

	if (!op_args) {
		err = SAB_LIB_STATUS(SAB_LIB_RSP_PROC_FAIL);
		return err;
	}

	op_args->stored_boot_mode = rsp->stored_boot_mode;

	return err;
}
