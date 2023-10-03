// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "internal/hsm_import_pub_key.h"
#include "sab_messaging.h"
#include "plat_utils.h"

#include "sab_import_pub_key.h"

uint32_t prepare_msg_import_pub_key(void *phdl,
				    void *cmd_buf, void *rsp_buf,
				    uint32_t *cmd_msg_sz,
				    uint32_t *rsp_msg_sz,
				    uint32_t msg_hdl,
				    void *args)
{
	uint32_t ret;
	struct sab_import_pub_key_msg *cmd =
		(struct sab_import_pub_key_msg *)cmd_buf;
	op_import_public_key_args_t *op_args =
		(op_import_public_key_args_t *)args;
	uint64_t phy_addr = 0;
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_CMD_MSG_PREP_FAIL);

	if (!op_args)
		return SAB_LIB_STATUS(SAB_LIB_CMD_MSG_PREP_FAIL);

	cmd->sig_ver_hdl = msg_hdl;

	ret = plat_os_abs_data_buf_v2((struct plat_os_abs_hdl *)phdl,
				      &phy_addr,
				      op_args->key,
				      op_args->key_size,
				      DATA_BUF_IS_INPUT);
	if (ret != PLAT_SUCCESS) {
		err |= ret;
		goto exit;
	}

	set_phy_addr_to_words(&cmd->key_addr,
			      0u,
			      phy_addr);

	cmd->key_size = op_args->key_size;
	cmd->key_type = op_args->key_type;
	cmd->flags = op_args->flags;

	*cmd_msg_sz = sizeof(struct sab_import_pub_key_msg);
	*rsp_msg_sz = sizeof(struct sab_import_pub_key_rsp);

	err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);
exit:
	return err;
}

uint32_t proc_msg_rsp_import_pub_key(void *rsp_buf, void *args)
{
	op_import_public_key_args_t *op_args = (op_import_public_key_args_t *)args;
	struct sab_import_pub_key_rsp *rsp =
		(struct sab_import_pub_key_rsp *)rsp_buf;

	if (!op_args)
		return SAB_LIB_STATUS(SAB_LIB_RSP_PROC_FAIL);

	*op_args->key_ref = rsp->key_ref;

	return SAB_LIB_STATUS(SAB_LIB_SUCCESS);
}
