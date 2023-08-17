// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "internal/hsm_key.h"
#include "internal/hsm_key_exchange.h"

#include "sab_key_exchange.h"
#include "sab_messaging.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_key_exchange(void *phdl,
				  void *cmd_buf, void *rsp_buf,
				  uint32_t *cmd_msg_sz,
				  uint32_t *rsp_msg_sz,
				  uint32_t msg_hdl,
				  void *args)
{
	uint32_t ret = SAB_ENGN_PASS;
	struct sab_cmd_key_exchange_msg *cmd =
		(struct sab_cmd_key_exchange_msg *)cmd_buf;
	op_key_exchange_args_t *op_args = (op_key_exchange_args_t *)args;
	uint64_t addr = 0;

	if (!op_args)
		return SAB_ENGN_FAIL;

	/* Send the signed message to platform if provided here. */
	if (op_args->signed_message) {
		(void)plat_os_abs_send_signed_message(phdl,
						      op_args->signed_message,
						      op_args->signed_msg_size);
	}

	addr = plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
				    op_args->shared_key_identifier_array,
				    op_args->shared_key_identifier_array_size,
				    (((op_args->flags &
				    HSM_OP_KEY_EXCHANGE_FLAGS_UPDATE) ==
				    HSM_OP_KEY_EXCHANGE_FLAGS_UPDATE)
				    ? DATA_BUF_IS_INPUT : 0u));

	if (!addr)
		return SAB_ENGN_FAIL;

	cmd->key_management_handle = msg_hdl;
	cmd->key_identifier = op_args->key_identifier;
	set_phy_addr_to_words(&cmd->shared_key_identifier_array,
			      0u,
			      addr);

	set_phy_addr_to_words(&cmd->ke_input_addr,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->ke_input,
						   op_args->ke_input_size,
						   DATA_BUF_IS_INPUT));
	set_phy_addr_to_words(&cmd->ke_output_addr,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->ke_output,
						   op_args->ke_output_size,
						   0u));
	set_phy_addr_to_words(&cmd->kdf_input_data,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->kdf_input,
						   op_args->kdf_input_size,
						   DATA_BUF_IS_INPUT));
	set_phy_addr_to_words(&cmd->kdf_output_data,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->kdf_output,
						   op_args->kdf_output_size,
						   0u));
	cmd->shared_key_group = op_args->shared_key_group;
	cmd->shared_key_info = op_args->shared_key_info;
	cmd->shared_key_type = op_args->shared_key_type;
	cmd->initiator_public_data_type = op_args->initiator_public_data_type;
	cmd->key_exchange_algorithm = op_args->key_exchange_scheme;
	cmd->kdf_algorithm = op_args->kdf_algorithm;
	cmd->ke_input_data_size = op_args->ke_input_size;
	cmd->ke_output_data_size = op_args->ke_output_size;
	cmd->shared_key_identifier_array_size = op_args->shared_key_identifier_array_size;
	cmd->kdf_input_size = op_args->kdf_input_size;
	cmd->kdf_output_size = op_args->kdf_output_size;
	cmd->flags = op_args->flags;
	cmd->crc = 0u;

	*cmd_msg_sz = sizeof(struct sab_cmd_key_exchange_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_key_exchange_rsp);

	return ret;
}

uint32_t proc_msg_rsp_key_exchange(void *rsp_buf, void *args)
{
	op_key_exchange_args_t *op_args =
		(op_key_exchange_args_t *)args;
	struct sab_cmd_key_exchange_rsp *rsp =
		(struct sab_cmd_key_exchange_rsp *)rsp_buf;

	return SAB_SUCCESS_STATUS;
}
