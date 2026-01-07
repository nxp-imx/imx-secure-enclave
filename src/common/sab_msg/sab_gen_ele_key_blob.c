// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include "internal/hsm_gen_ele_key_blob.h"

#include "sab_gen_ele_key_blob.h"
#include "sab_messaging.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_gen_ele_key_blob(void *phdl, void *cmd_buf, void *rsp_buf,
				      uint32_t *cmd_msg_sz, uint32_t *rsp_msg_sz,
				      uint32_t msg_hdl, void *args)
{
	struct rom_cmd_gen_ele_key_blob_msg *cmd =
			(struct rom_cmd_gen_ele_key_blob_msg *)cmd_buf;
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_CMD_MSG_PREP_FAIL);
	op_gen_ele_key_blob_msg_args_t *op_args = args;
	uint64_t temp;
	uint32_t ret;

	if (!op_args)
		return err;

	cmd->key_id = op_args->key_id;

	ret = plat_os_abs_data_buf_v2((struct plat_os_abs_hdl *)phdl,
				      &temp, (uint8_t *)op_args->load_addr,
				      op_args->load_addr_sz, DATA_BUF_IS_INPUT);
	if (ret != PLAT_SUCCESS) {
		err |= ret;
		return err;
	}
	set_phy_addr_to_words(&cmd->load_addr, 0, temp);

	ret = plat_os_abs_data_buf_v2((struct plat_os_abs_hdl *)phdl,
				      &temp, (uint8_t *)op_args->store_addr,
				      op_args->store_addr_sz, DATA_BUF_IS_OUTPUT);
	if (ret != PLAT_SUCCESS) {
		err |= ret;
		return err;
	}
	set_phy_addr_to_words(&cmd->store_addr, 0, temp);

	cmd->max_export_sz = op_args->max_export_sz;

	*cmd_msg_sz = sizeof(struct rom_cmd_gen_ele_key_blob_msg);
	*rsp_msg_sz = sizeof(struct rom_cmd_gen_ele_key_blob_rsp);

	return SAB_LIB_STATUS(SAB_LIB_SUCCESS);
}

uint32_t proc_msg_rsp_gen_ele_key_blob(void *rsp_buf, void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);

	return err;
}
