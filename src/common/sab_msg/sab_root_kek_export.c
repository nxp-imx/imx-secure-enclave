// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "internal/hsm_root_kek_export.h"
#include "sab_root_kek_export.h"
#include "sab_messaging.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_root_kek_export(void *phdl,
				     void *cmd_buf, void *rsp_buf,
				     uint32_t *cmd_msg_sz,
				     uint32_t *rsp_msg_sz,
				     uint32_t msg_hdl,
				     void *args)
{
	uint32_t ret;
	struct sab_root_kek_export_msg *cmd =
		(struct sab_root_kek_export_msg *)cmd_buf;
	op_export_root_kek_args_t *op_args =
		(op_export_root_kek_args_t *)args;
	uint64_t phy_addr = 0;
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_CMD_MSG_PREP_FAIL);

	if (!op_args)
		return SAB_LIB_STATUS(SAB_LIB_CMD_MSG_PREP_FAIL);

	cmd->session_handle = msg_hdl;
	cmd->root_kek_address_ext = 0;
	ret = plat_os_abs_data_buf_v2((struct plat_os_abs_hdl *)phdl,
				      &phy_addr,
				      op_args->out_root_kek,
				      op_args->root_kek_size,
				      0u);
	if (ret != PLAT_SUCCESS) {
		err |= ret;
		goto exit;
	}

	set_phy_addr_to_words(&cmd->root_kek_address,
			      0u,
			      phy_addr);

	cmd->flags = op_args->flags;
	cmd->root_kek_size = op_args->root_kek_size;
	cmd->reserved = 0u;
	cmd->crc = 0;

	*cmd_msg_sz = sizeof(struct sab_root_kek_export_msg);
	*rsp_msg_sz = sizeof(struct sab_root_kek_export_rsp);

	err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);
exit:
	return err;
}

uint32_t proc_msg_rsp_root_kek_export(void *rsp_buf, void *args)
{
	struct sab_root_kek_export_rsp *rsp =
		(struct sab_root_kek_export_rsp *)rsp_buf;

	return SAB_LIB_STATUS(SAB_LIB_SUCCESS);
}
