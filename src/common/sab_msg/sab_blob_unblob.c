// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include "internal/hsm_blob_unblob.h"

#include "sab_blob_unblob.h"
#include "sab_messaging.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_blob_unblob(void *phdl, void *cmd_buf, void *rsp_buf,
				 uint32_t *cmd_msg_sz, uint32_t *rsp_msg_sz,
				 uint32_t msg_hdl, void *args)
{
	struct rom_cmd_blob_unblob_msg *cmd =
			(struct rom_cmd_blob_unblob_msg *)cmd_buf;
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_CMD_MSG_PREP_FAIL);
	op_blob_unblob_msg_args_t *op_args = args;
	uint64_t temp;
	uint32_t ret;

	if (!op_args)
		return err;

	ret = plat_os_abs_data_buf_v2((struct plat_os_abs_hdl *)phdl,
				      &temp, (uint8_t *)op_args->in_addr,
				      op_args->in_size, DATA_BUF_IS_INPUT);
	if (ret != PLAT_SUCCESS) {
		err |= ret;
		return err;
	}
	set_phy_addr_to_words(&cmd->in_lsb_addr, &cmd->in_msb_addr, temp);

	ret = plat_os_abs_data_buf_v2((struct plat_os_abs_hdl *)phdl,
				      &temp, (uint8_t *)op_args->out_addr,
				      op_args->out_size, DATA_BUF_IS_OUTPUT);
	if (ret != PLAT_SUCCESS) {
		err |= ret;
		return err;
	}
	set_phy_addr_to_words(&cmd->out_lsb_addr, &cmd->out_msb_addr, temp);

	if (op_args->usr_ctx_addr) {
		ret = plat_os_abs_data_buf_v2((struct plat_os_abs_hdl *)phdl,
					      &temp, (uint8_t *)op_args->usr_ctx_addr,
					      op_args->usr_ctx_size, DATA_BUF_IS_INPUT);
		if (ret != PLAT_SUCCESS) {
			err |= ret;
			return err;
		}
	}
	set_phy_addr_to_words(&cmd->usr_ctx_lsb_addr, &cmd->usr_ctx_msb_addr, temp);

	cmd->in_size = op_args->in_size;
	cmd->out_size = op_args->out_size;
	cmd->usr_ctx_size = op_args->usr_ctx_size;
	cmd->flags = op_args->flags;
	cmd->mode = op_args->mode;

	*cmd_msg_sz = sizeof(struct rom_cmd_blob_unblob_msg);
	*rsp_msg_sz = sizeof(struct rom_cmd_blob_unblob_rsp);

	return SAB_LIB_STATUS(SAB_LIB_SUCCESS);
}

uint32_t proc_msg_rsp_blob_unblob(void *rsp_buf, void *args)
{
	struct rom_cmd_blob_unblob_rsp *rsp =
			(struct rom_cmd_blob_unblob_rsp *)rsp_buf;
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);
	op_blob_unblob_msg_args_t *op_args = args;

	if (op_args)
		op_args->exp_out_size = rsp->out_size;

	return err;
}
