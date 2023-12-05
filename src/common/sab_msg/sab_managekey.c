// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include "internal/hsm_managekey.h"

#include "sab_managekey.h"
#include "sab_messaging.h"
#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_managekey(void *phdl,
			       void *cmd_buf, void *rsp_buf,
			       uint32_t *cmd_msg_sz,
			       uint32_t *rsp_msg_sz,
			       uint32_t msg_hdl,
			       void *args)
{
	uint32_t ret = SAB_ENGN_PASS;
	struct sab_cmd_manage_key_msg *cmd =
		(struct sab_cmd_manage_key_msg *) cmd_buf;
	struct sab_cmd_manage_key_rsp *rsp =
		(struct sab_cmd_manage_key_rsp *) rsp_buf;
	op_manage_key_args_t *op_args = (op_manage_key_args_t *) args;

	if (!op_args)
		return SAB_ENGN_FAIL;

	cmd->key_management_handle = msg_hdl;
	cmd->dest_key_identifier = *(op_args->key_identifier);
	cmd->kek_id = op_args->kek_identifier;
	cmd->input_data_size = op_args->input_size;
	cmd->flags = op_args->flags;
	cmd->key_type = op_args->key_type;
	cmd->key_group = op_args->key_group;
	cmd->key_info = op_args->key_info;
	set_phy_addr_to_words(&cmd->input_data_addr,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->input_data,
						   op_args->input_size,
						   DATA_BUF_IS_INPUT));

	*cmd_msg_sz = sizeof(struct sab_cmd_manage_key_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_manage_key_rsp);

	cmd->crc = 0u;

	return ret;
}

uint32_t proc_msg_rsp_managekey(void *rsp_buf, void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);
	op_manage_key_args_t *op_args = (op_manage_key_args_t *) args;
	struct sab_cmd_manage_key_rsp *rsp =
		(struct sab_cmd_manage_key_rsp *) rsp_buf;

	if (!op_args) {
		err = SAB_LIB_STATUS(SAB_LIB_ERROR);
		goto exit;
	}

	if ((op_args->flags & HSM_OP_MANAGE_KEY_FLAGS_IMPORT_CREATE)
			== HSM_OP_MANAGE_KEY_FLAGS_IMPORT_CREATE) {
		*(op_args->key_identifier) = rsp->key_identifier;
	}
exit:
	return err;
}

uint32_t prepare_msg_managekey_ext(void *phdl,
			       void *cmd_buf, void *rsp_buf,
			       uint32_t *cmd_msg_sz,
			       uint32_t *rsp_msg_sz,
			       uint32_t msg_hdl,
			       void *args)
{
	uint32_t ret = SAB_ENGN_PASS;
	struct sab_cmd_manage_key_ext_msg *cmd =
		(struct sab_cmd_manage_key_ext_msg *) cmd_buf;
	struct sab_cmd_manage_key_rsp *rsp =
		(struct sab_cmd_manage_key_rsp *) rsp_buf;
	op_manage_key_ext_args_t *op_args = (op_manage_key_ext_args_t *) args;

	if (!op_args)
		return SAB_ENGN_FAIL;

	cmd->key_management_handle = msg_hdl;
	cmd->dest_key_identifier = *(op_args->key_identifier);
	cmd->kek_id = op_args->kek_identifier;
	cmd->input_data_size = op_args->input_size;
	cmd->flags = op_args->flags;
	cmd->key_type = op_args->key_type;
	cmd->key_group = op_args->key_group;
	cmd->key_info = op_args->key_info;
	set_phy_addr_to_words(&cmd->input_data_addr,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->input_data,
						   op_args->input_size,
						   DATA_BUF_IS_INPUT));

	cmd->min_mac_len = op_args->min_mac_len;
	cmd->reserved[0] = op_args->reserved[0];
	cmd->reserved[1] = op_args->reserved[1];
	cmd->reserved[2] = op_args->reserved[2];

	*cmd_msg_sz = sizeof(struct sab_cmd_manage_key_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_manage_key_rsp);

	cmd->crc = 0u;

	return ret;
}
