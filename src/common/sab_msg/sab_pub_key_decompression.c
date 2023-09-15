// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include "internal/hsm_pub_key_decompression.h"

#include "sab_pub_key_decompression.h"
#include "sab_messaging.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_pub_key_decompression(void *phdl,
					   void *cmd_buf, void *rsp_buf,
					   uint32_t *cmd_msg_sz,
					   uint32_t *rsp_msg_sz,
					   uint32_t msg_hdl,
					   void *args)
{
	uint32_t ret;
	struct sab_public_key_decompression_msg *cmd =
		(struct sab_public_key_decompression_msg *)cmd_buf;
	op_pub_key_dec_args_t *op_args = (op_pub_key_dec_args_t *)args;
	uint64_t phy_addr = 0;
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_CMD_MSG_PREP_FAIL);

	if (!op_args)
		return SAB_LIB_STATUS(SAB_LIB_CMD_MSG_PREP_FAIL);

	cmd->sesssion_handle = msg_hdl;
	cmd->input_address_ext = 0u;
	ret = plat_os_abs_data_buf_v2((struct plat_os_abs_hdl *)phdl,
				      &phy_addr,
				      op_args->key,
				      op_args->key_size,
				      DATA_BUF_IS_INPUT);
	if (ret != PLAT_SUCCESS) {
		err |= ret;
		goto exit;
	}

	set_phy_addr_to_words(&cmd->input_address,
			      0u,
			      phy_addr);

	cmd->output_address_ext = 0u;

	ret = plat_os_abs_data_buf_v2((struct plat_os_abs_hdl *)phdl,
				      &phy_addr,
				      op_args->out_key,
				      op_args->out_key_size,
				      0u);
	if (ret != PLAT_SUCCESS) {
		err |= ret;
		goto exit;
	}

	set_phy_addr_to_words(&cmd->output_address,
			      0u,
			      phy_addr);

	cmd->input_size = op_args->key_size;
	cmd->out_size = op_args->out_key_size;
	cmd->key_type = op_args->key_type;
	cmd->flags = op_args->flags;
	cmd->rsv = 0u;
	cmd->crc = 0u;

	*cmd_msg_sz = sizeof(struct sab_public_key_decompression_msg);
	*rsp_msg_sz = sizeof(struct sab_public_key_decompression_rsp);

	err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);
exit:
	return err;
}

uint32_t proc_msg_rsp_pub_key_decompression(void *rsp_buf, void *args)
{
	struct sab_public_key_decompression_rsp *rsp =
		(struct sab_public_key_decompression_rsp *)rsp_buf;

	return SAB_LIB_STATUS(SAB_LIB_SUCCESS);
}
