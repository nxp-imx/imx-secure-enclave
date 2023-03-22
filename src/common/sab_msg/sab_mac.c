/*
 * Copyright 2022-2023 NXP
 *
 * NXP Confidential.
 * This software is owned or controlled by NXP and may only be used strictly
 * in accordance with the applicable license terms.  By expressly accepting
 * such terms or by downloading, installing, activating and/or otherwise using
 * the software, you are agreeing that you have read, and that you agree to
 * comply with and are bound by, such license terms.  If you do not agree to be
 * bound by the applicable license terms, then you may not retain, install,
 * activate or otherwise use the software.
 */

#include <string.h>

#include "internal/hsm_mac.h"
#include "sab_mac.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_mac_one_go(void *phdl,
				void *cmd_buf, void *rsp_buf,
				uint32_t *cmd_msg_sz,
				uint32_t *rsp_msg_sz,
				uint32_t msg_hdl,
				void *args)
{
	int32_t ret = 0;
	uint32_t mac_size_bytes = 0;
	struct sab_cmd_mac_one_go_msg *cmd =
		(struct sab_cmd_mac_one_go_msg *) cmd_buf;
	struct sab_cmd_mac_one_go_rsp *rsp =
		(struct sab_cmd_mac_one_go_rsp *) rsp_buf;
	op_mac_one_go_args_t *op_args = (op_mac_one_go_args_t *) args;

	cmd->mac_handle = msg_hdl;
	cmd->key_id = op_args->key_identifier;

	cmd->algorithm = op_args->algorithm;
	cmd->flags = op_args->flags;

#ifdef PSA_COMPLIANT
	mac_size_bytes = op_args->mac_size;
#else
	if (op_args->flags & HSM_OP_MAC_ONE_GO_FLAGS_MAC_LENGTH_IN_BITS) {
		mac_size_bytes = op_args->mac_size / 8;
		if (op_args->mac_size % 8) {
			mac_size_bytes++;
		}
	} else {
		mac_size_bytes = op_args->mac_size;
	}

	if (op_args->payload_size > UINT16_MAX)
		return SAB_FAILURE_STATUS;

#endif

	cmd->payload_address = (uint32_t)plat_os_abs_data_buf(
						phdl,
						op_args->payload,
						op_args->payload_size,
						DATA_BUF_IS_INPUT);

	if ((op_args->flags & HSM_OP_MAC_ONE_GO_FLAGS_MAC_GENERATION)
			== HSM_OP_MAC_ONE_GO_FLAGS_MAC_GENERATION) {
		cmd->mac_address = (uint32_t)plat_os_abs_data_buf(
						phdl,
						op_args->mac,
						mac_size_bytes,
						DATA_BUF_IS_OUTPUT);
	} else {
		cmd->mac_address = (uint32_t)plat_os_abs_data_buf(
						phdl,
						op_args->mac,
						mac_size_bytes,
						DATA_BUF_IS_INPUT);
	}
	cmd->payload_size = op_args->payload_size;
	cmd->mac_size = op_args->mac_size;
	/* No need to set the reserved structure member to zero,
	 * as buffer "cmd_msg_sz", is memset to zero by the caller
	 * "process_sab_msg".
	 */
	cmd->crc = 0u;

	*cmd_msg_sz = sizeof(struct sab_cmd_mac_one_go_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_mac_one_go_rsp);

	return ret;
}

uint32_t proc_msg_rsp_mac_one_go(void *rsp_buf, void *args)
{
	op_mac_one_go_args_t *op_args = (op_mac_one_go_args_t *) args;
	struct sab_cmd_mac_one_go_rsp *rsp =
		(struct sab_cmd_mac_one_go_rsp *) rsp_buf;

	op_args->verification_status = rsp->verification_status;
#ifdef PSA_COMPLIANT
	op_args->expected_mac_size = rsp->output_mac_size;
#endif
	return SAB_SUCCESS_STATUS;
}

uint32_t prepare_msg_mac_open_req(void *phdl,
				     void *cmd_buf, void *rsp_buf,
				     uint32_t *cmd_msg_sz,
				     uint32_t *rsp_msg_sz,
				     uint32_t msg_hdl,
				     void *args)
{
	uint32_t ret = 0;
	struct sab_cmd_mac_open_msg *cmd =
		(struct sab_cmd_mac_open_msg *) cmd_buf;
	struct sab_cmd_mac_open_rsp *rsp =
		(struct sab_cmd_mac_open_rsp *) rsp_buf;
	open_svc_mac_args_t *op_args = (open_svc_mac_args_t *) args;

#ifndef PSA_COMPLIANT
	cmd->flags = op_args->flags;
#endif
	cmd->key_store_handle = msg_hdl;

	*cmd_msg_sz = sizeof(struct sab_cmd_mac_open_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_mac_open_rsp);

	return ret;
}

uint32_t proc_msg_rsp_mac_open_req(void *rsp_buf, void *args)
{
	struct sab_cmd_mac_open_rsp *rsp =
		(struct sab_cmd_mac_open_rsp *) rsp_buf;
	open_svc_mac_args_t *op_args = (open_svc_mac_args_t *) args;

	op_args->mac_serv_hdl = rsp->mac_handle;

	return SAB_SUCCESS_STATUS;
}

uint32_t prepare_msg_mac_close_req(void *phdl,
				      void *cmd_buf, void *rsp_buf,
				      uint32_t *cmd_msg_sz,
				      uint32_t *rsp_msg_sz,
				      uint32_t msg_hdl,
				      void *args)
{
	uint32_t ret = 0;
	struct sab_cmd_mac_close_msg *cmd =
		(struct sab_cmd_mac_close_msg *) cmd_buf;
	struct sab_cmd_mac_close_rsp *rsp =
		(struct sab_cmd_mac_close_rsp *) rsp_buf;

	*cmd_msg_sz = sizeof(struct sab_cmd_mac_close_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_mac_close_rsp);

	cmd->mac_handle = msg_hdl;

	return ret;
}

uint32_t proc_msg_rsp_mac_close_req(void *rsp_buf, void *args)
{
	return SAB_SUCCESS_STATUS;
}
