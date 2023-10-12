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
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_CMD_MSG_PREP_FAIL);
	struct sab_cmd_key_exchange_msg *cmd =
		(struct sab_cmd_key_exchange_msg *)cmd_buf;
	op_key_exchange_args_t *op_args = (op_key_exchange_args_t *)args;
	uint64_t phy_addr = 0;
	uint32_t ret;

	if (!op_args)
		return err;

#ifndef PSA_COMPLIANT
	/* Send the signed message to platform if provided here. */
	if (op_args->signed_message) {
		ret = plat_os_abs_send_signed_message_v2(phdl,
							 op_args->signed_message,
							 op_args->signed_msg_size);
		if (ret != PLAT_SUCCESS) {
			err |= ret;
			goto exit;
		}

	}

	ret = plat_os_abs_data_buf_v2((struct plat_os_abs_hdl *)phdl,
				      &phy_addr,
				      op_args->shared_key_identifier_array,
				      op_args->shared_key_identifier_array_size,
				      (((op_args->flags &
				      HSM_OP_KEY_EXCHANGE_FLAGS_UPDATE) ==
				      HSM_OP_KEY_EXCHANGE_FLAGS_UPDATE)
				      ? DATA_BUF_IS_INPUT : 0u));

	if (ret != PLAT_SUCCESS) {
		err |= ret;
		goto exit;
	}

	cmd->key_identifier = op_args->key_identifier;
	set_phy_addr_to_words(&cmd->shared_key_identifier_array,
			      0u,
			      phy_addr);

	ret =  plat_os_abs_data_buf_v2((struct plat_os_abs_hdl *)phdl,
				       &phy_addr,
				       op_args->ke_input,
				       op_args->ke_input_size,
				       DATA_BUF_IS_INPUT);

	if (ret != PLAT_SUCCESS) {
		err |= ret;
		goto exit;
	}

	set_phy_addr_to_words(&cmd->ke_input_addr,
			      0u,
			      phy_addr);

	ret = plat_os_abs_data_buf_v2((struct plat_os_abs_hdl *)phdl,
				      &phy_addr,
				      op_args->ke_output,
				      op_args->ke_output_size,
				      0u);

	if (ret != PLAT_SUCCESS) {
		err |= ret;
		goto exit;
	}

	set_phy_addr_to_words(&cmd->ke_output_addr,
			      0u,
			      phy_addr);

	ret = plat_os_abs_data_buf_v2((struct plat_os_abs_hdl *)phdl,
				      &phy_addr,
				      op_args->kdf_input,
				      op_args->kdf_input_size,
				      DATA_BUF_IS_INPUT);

	if (ret != PLAT_SUCCESS) {
		err |= ret;
		goto exit;
	}

	set_phy_addr_to_words(&cmd->kdf_input_data,
			      0u,
			      phy_addr);

	ret = plat_os_abs_data_buf_v2((struct plat_os_abs_hdl *)phdl,
				      &phy_addr,
				      op_args->kdf_output,
				      op_args->kdf_output_size,
				      0u);

	if (ret != PLAT_SUCCESS) {
		err |= ret;
		goto exit;
	}

	set_phy_addr_to_words(&cmd->kdf_output_data,
			      0u,
			      phy_addr);

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
#else
	cmd->signed_content_sz = op_args->signed_content_sz;
	ret = plat_os_abs_data_buf_v2((struct plat_os_abs_hdl *)phdl,
				      &phy_addr,
				      op_args->signed_content,
				      op_args->signed_content_sz,
				      DATA_BUF_IS_INPUT);

	if (ret != PLAT_SUCCESS) {
		err |= ret;
		goto exit;
	}

	set_phy_addr_to_words(&cmd->signed_content_addr,
			      0u,
			      phy_addr);

	cmd->peer_pubkey_sz = op_args->peer_pubkey_sz;
	ret = plat_os_abs_data_buf_v2((struct plat_os_abs_hdl *)phdl,
				      &phy_addr,
				      op_args->peer_pubkey,
				      op_args->peer_pubkey_sz,
				      DATA_BUF_IS_INPUT);

	if (ret != PLAT_SUCCESS) {
		err |= ret;
		goto exit;
	}

	set_phy_addr_to_words(&cmd->peer_pubkey_addr,
			      0u,
			      phy_addr);

	cmd->user_fixed_info_sz = op_args->user_fixed_info_sz;
	ret = plat_os_abs_data_buf_v2((struct plat_os_abs_hdl *)phdl,
				      &phy_addr,
				      op_args->user_fixed_info,
				      op_args->user_fixed_info_sz,
				      DATA_BUF_IS_INPUT);

	if (ret != PLAT_SUCCESS) {
		err |= ret;
		goto exit;
	}

	set_phy_addr_to_words(&cmd->user_fixed_info_addr,
			      0u,
			      phy_addr);
#endif
	cmd->key_management_handle = msg_hdl;
	cmd->flags = op_args->flags;
	cmd->crc = 0u;

	*cmd_msg_sz = sizeof(struct sab_cmd_key_exchange_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_key_exchange_rsp);

	err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);
exit:
	return err;
}

uint32_t proc_msg_rsp_key_exchange(void *rsp_buf, void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);
	op_key_exchange_args_t *op_args =
		(op_key_exchange_args_t *)args;
	struct sab_cmd_key_exchange_rsp *rsp =
		(struct sab_cmd_key_exchange_rsp *)rsp_buf;

#ifdef PSA_COMPLIANT
	op_args->out_derived_key_id = rsp->derived_key_id;
	op_args->out_salt_sz = rsp->salt_sz;
#endif
	return err;
}
