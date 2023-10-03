// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "internal/hsm_key_exchange.h"
#include "sab_messaging.h"
#include "plat_utils.h"

#include "sab_tls_finish.h"

uint32_t prepare_msg_tls_finish(void *phdl,
				void *cmd_buf, void *rsp_buf,
				uint32_t *cmd_msg_sz,
				uint32_t *rsp_msg_sz,
				uint32_t msg_hdl,
				void *args)
{
	uint32_t ret;
	struct sab_cmd_tls_finish_msg *cmd =
		(struct sab_cmd_tls_finish_msg *)cmd_buf;
	op_tls_finish_args_t *op_args =
		(op_tls_finish_args_t *)args;
	uint64_t phy_addr = 0;
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_CMD_MSG_PREP_FAIL);

	if (!op_args)
		return SAB_LIB_STATUS(SAB_LIB_CMD_MSG_PREP_FAIL);

	cmd->key_management_handle = msg_hdl;
	cmd->key_identifier = op_args->key_identifier;

	ret = plat_os_abs_data_buf_v2((struct plat_os_abs_hdl *)phdl,
				      &phy_addr,
				      op_args->handshake_hash_input,
				      op_args->handshake_hash_input_size,
				      DATA_BUF_IS_INPUT);
	if (ret != PLAT_SUCCESS) {
		err |= ret;
		goto exit;
	}

	set_phy_addr_to_words(&cmd->handshake_hash_input_addr,
			      0u,
			      phy_addr);

	ret = plat_os_abs_data_buf_v2((struct plat_os_abs_hdl *)phdl,
				      &phy_addr,
				      op_args->verify_data_output,
				      op_args->verify_data_output_size,
				      0u);
	if (ret != PLAT_SUCCESS) {
		err |= ret;
		goto exit;
	}

	set_phy_addr_to_words(&cmd->verify_data_output_addr,
			      0u,
			      phy_addr);

	cmd->handshake_hash_input_size = op_args->handshake_hash_input_size;
	cmd->verify_data_output_size = op_args->verify_data_output_size;
	cmd->flags = op_args->flags;
	cmd->hash_algorithm = op_args->hash_algorithm;
	cmd->reserved = 0;
	cmd->crc = 0u;

	*cmd_msg_sz = sizeof(struct sab_cmd_tls_finish_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_tls_finish_rsp);

	err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);
exit:
	return err;
}

uint32_t proc_msg_rsp_tls_finish(void *rsp_buf, void *args)
{
	struct sab_cmd_tls_finish_rsp *rsp =
		(struct sab_cmd_tls_finish_rsp *)rsp_buf;

	return SAB_LIB_STATUS(SAB_LIB_SUCCESS);
}
