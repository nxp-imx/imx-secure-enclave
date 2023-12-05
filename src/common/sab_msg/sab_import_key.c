// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include "internal/hsm_importkey.h"

#include "sab_import_key.h"
#include "sab_messaging.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_importkey(void *phdl,
			       void *cmd_buf, void *rsp_buf,
			       uint32_t *cmd_msg_sz,
			       uint32_t *rsp_msg_sz,
			       uint32_t msg_hdl,
			       void *args)
{
	uint32_t ret = SAB_ENGN_PASS;
	struct sab_cmd_import_key_msg *cmd =
		(struct sab_cmd_import_key_msg *) cmd_buf;
	op_import_key_args_t *op_args = (op_import_key_args_t *) args;

	if (!op_args)
		return SAB_ENGN_FAIL;

	cmd->key_management_hdl = msg_hdl;
	cmd->flags = op_args->flags;
	if (!(cmd->flags & HSM_OP_IMPORT_KEY_INPUT_E2GO_TLV))
		cmd->key_group = op_args->key_group;

	set_phy_addr_to_words(&cmd->input_lsb_addr,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->input_lsb_addr,
						   op_args->input_size,
						   DATA_BUF_IS_INPUT));
	cmd->input_size = op_args->input_size;

	*cmd_msg_sz = sizeof(struct sab_cmd_import_key_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_import_key_rsp);

	cmd->crc = 0u;

	return ret;
}

uint32_t proc_msg_rsp_importkey(void *rsp_buf, void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);
	op_import_key_args_t *op_args = (op_import_key_args_t *) args;
	struct sab_cmd_import_key_rsp *rsp =
		(struct sab_cmd_import_key_rsp *) rsp_buf;

	if (!op_args) {
		err = SAB_LIB_STATUS(SAB_LIB_RSP_PROC_FAIL);
		goto exit;
	}

	op_args->key_identifier = rsp->key_identifier;
exit:
	return err;
}
