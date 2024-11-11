// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2024 NXP
 */

#include <string.h>

#include "common/mac.h"
#include "sab_mac.h"
#include "sab_messaging.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_mac(void *phdl,
			 void *cmd_buf, void *rsp_buf,
			 uint32_t *cmd_msg_sz,
			 uint32_t *rsp_msg_sz,
			 uint32_t msg_hdl,
			 void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_CMD_MSG_PREP_FAIL);
	uint32_t mac_size_bytes = 0;
	struct sab_cmd_mac_msg *cmd =
		(struct sab_cmd_mac_msg *)cmd_buf;
	op_mac_args_t *op_args = (op_mac_args_t *)args;
	uint64_t phy_addr = 0;
	uint32_t ret;

	if (!op_args)
		goto exit;

	cmd->mac_handle = msg_hdl;
	cmd->algorithm = op_args->algorithm;
	cmd->flags = op_args->flags;
#ifdef PSA_COMPLIANT
	cmd->key_type = op_args->key_type;
	cmd->key_size = op_args->key_size;
	if (op_args->flags & MAC_OP_FLAGS_PLAINTEXT_KEY) {
		ret = plat_os_abs_data_buf_v2((struct plat_os_abs_hdl *)phdl,
					      &phy_addr,
					      op_args->key,
					      op_args->key_size,
					      DATA_BUF_IS_INPUT);

		if (ret != PLAT_SUCCESS) {
			err |= ret;
			goto exit;
		}

		set_phy_addr_to_words(&cmd->key,
				      0u,
				      phy_addr);
	} else {
		cmd->key = op_args->key_identifier;
	}

	cmd->context_size = op_args->context_size;
	ret = plat_os_abs_data_buf_v2((struct plat_os_abs_hdl *)phdl,
				      &phy_addr,
				      op_args->context,
				      op_args->context_size,
				      DATA_BUF_IS_IN_OUT);

	if (ret != PLAT_SUCCESS) {
		err |= ret;
		goto exit;
	}

	set_phy_addr_to_words(&cmd->context_address,
			      0u,
			      phy_addr);

	mac_size_bytes = op_args->mac_size;
#else
	cmd->key = op_args->key_identifier;

	if (op_args->flags & MAC_OP_FLAGS_MAC_LENGTH_IN_BITS) {
		mac_size_bytes = op_args->mac_size / 8;
		if (op_args->mac_size % 8) {
			mac_size_bytes++;
		}
	} else {
		mac_size_bytes = op_args->mac_size;
	}

	if (op_args->payload_size > UINT16_MAX)
		goto exit;

#endif
	ret = plat_os_abs_data_buf_v2((struct plat_os_abs_hdl *)phdl,
				      &phy_addr,
				      op_args->payload,
				      op_args->payload_size,
				      DATA_BUF_IS_INPUT);

	if (ret != PLAT_SUCCESS) {
		err |= ret;
		goto exit;
	}

	set_phy_addr_to_words(&cmd->payload_address,
			      0u,
			      phy_addr);

	ret = plat_os_abs_data_buf_v2((struct plat_os_abs_hdl *)phdl,
				      &phy_addr,
				      op_args->mac,
				      mac_size_bytes,
				      DATA_BUF_IS_IN_OUT);

	if (ret != PLAT_SUCCESS) {
		err |= ret;
		goto exit;
	}

	set_phy_addr_to_words(&cmd->mac_address,
			      0u,
			      phy_addr);

	cmd->payload_size = op_args->payload_size;
	cmd->mac_size = op_args->mac_size;
	/* No need to set the reserved structure member to zero,
	 * as buffer "cmd_msg_sz", is memset to zero by the caller
	 * "process_sab_msg".
	 */
	cmd->crc = 0u;

	*cmd_msg_sz = sizeof(struct sab_cmd_mac_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_mac_rsp);

	err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);
exit:
	return err;
}

uint32_t proc_msg_rsp_mac(void *rsp_buf, void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_RSP_PROC_FAIL);
	op_mac_args_t *op_args = (op_mac_args_t *)args;
	struct sab_cmd_mac_rsp *rsp =
		(struct sab_cmd_mac_rsp *)rsp_buf;

	if (!op_args)
		goto exit;

	op_args->verification_status = rsp->verification_status;
#ifdef PSA_COMPLIANT
	op_args->exp_mac_size = rsp->output_size;
	op_args->exp_output_size = rsp->output_size;
#endif
	err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);
exit:
	return err;
}

uint32_t prepare_msg_mac_open_req(void *phdl,
				     void *cmd_buf, void *rsp_buf,
				     uint32_t *cmd_msg_sz,
				     uint32_t *rsp_msg_sz,
				     uint32_t msg_hdl,
				     void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);
	struct sab_cmd_mac_open_msg *cmd =
		(struct sab_cmd_mac_open_msg *) cmd_buf;
#ifndef PSA_COMPLIANT
	open_svc_mac_args_t *op_args = (open_svc_mac_args_t *) args;

	if (!op_args)
		return SAB_LIB_STATUS(SAB_LIB_CMD_MSG_PREP_FAIL);

	cmd->flags = op_args->flags;
#endif
	cmd->key_store_handle = msg_hdl;

	*cmd_msg_sz = sizeof(struct sab_cmd_mac_open_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_mac_open_rsp);

	return err;
}

uint32_t proc_msg_rsp_mac_open_req(void *rsp_buf, void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_RSP_PROC_FAIL);
	struct sab_cmd_mac_open_rsp *rsp =
		(struct sab_cmd_mac_open_rsp *) rsp_buf;
	open_svc_mac_args_t *op_args = (open_svc_mac_args_t *) args;

	if (!op_args)
		goto exit;

	op_args->mac_serv_hdl = rsp->mac_handle;

	err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);
exit:
	return err;
}

uint32_t prepare_msg_mac_close_req(void *phdl,
				      void *cmd_buf, void *rsp_buf,
				      uint32_t *cmd_msg_sz,
				      uint32_t *rsp_msg_sz,
				      uint32_t msg_hdl,
				      void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);
	struct sab_cmd_mac_close_msg *cmd =
		(struct sab_cmd_mac_close_msg *) cmd_buf;

	*cmd_msg_sz = sizeof(struct sab_cmd_mac_close_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_mac_close_rsp);

	cmd->mac_handle = msg_hdl;

	return err;
}

uint32_t proc_msg_rsp_mac_close_req(void *rsp_buf, void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);

	return err;
}
