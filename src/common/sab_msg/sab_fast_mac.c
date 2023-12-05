// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "sab_messaging.h"
#include "sab_fast_mac.h"
#include "internal/she_fast_mac.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_fast_mac(void *phdl,
			      void *cmd_buf,
			      void *rsp_buf,
			      uint32_t *cmd_msg_sz,
			      uint32_t *rsp_msg_sz,
			      uint32_t msg_hdl,
			      void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);
	struct sab_she_fast_mac_msg *cmd =
		(struct sab_she_fast_mac_msg *)cmd_buf;

	op_fast_seco_mac_t *op_args = (op_fast_seco_mac_t *)args;

	cmd->utils_handle = msg_hdl;
	cmd->key_id = op_args->key_id;
	cmd->data_length = op_args->data_length;
	cmd->data_offset = op_args->data_offset;
	cmd->mac_length = op_args->mac_length;
	cmd->flags = op_args->flags;

	*cmd_msg_sz = sizeof(struct sab_she_fast_mac_msg);
	*rsp_msg_sz = sizeof(struct sab_she_fast_mac_rsp);

	return err;
}

uint32_t prepare_msg_v2x_fast_mac(void *phdl,
				  void *cmd_buf,
				  void *rsp_buf,
				  uint32_t *cmd_msg_sz,
				  uint32_t *rsp_msg_sz,
				  uint32_t msg_hdl,
				  void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);
	struct sab_she_v2x_fast_mac_msg *cmd =
		(struct sab_she_v2x_fast_mac_msg *)cmd_buf;

	op_fast_v2x_mac_t *op_args = (op_fast_v2x_mac_t *)args;

	cmd->utils_handle = msg_hdl;
	cmd->key_id = op_args->key_id;
	cmd->data_length = op_args->data_length;
	cmd->mac_length = op_args->mac_length;
	cmd->flags = op_args->flags;
	cmd->m1 = op_args->m1;
	cmd->m2 = op_args->m2;
	cmd->m3 = op_args->m3;
	cmd->m4 = op_args->m4;

	*cmd_msg_sz = sizeof(struct sab_she_v2x_fast_mac_msg);
	*rsp_msg_sz = sizeof(struct sab_she_fast_mac_rsp);

	return err;
}

uint32_t proc_msg_rsp_fast_mac(void *rsp_buf, void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);
	struct sab_she_fast_mac_rsp *rsp =
		(struct sab_she_fast_mac_rsp *)rsp_buf;

	op_fast_seco_mac_t *op_args = (op_fast_seco_mac_t *)args;

	if (GET_STATUS_CODE(rsp->rsp_code) == SAB_FAILURE_STATUS)
		return err;

	if (op_args->flags & SHE_FAST_MAC_FLAGS_VERIFICATION)
		op_args->verification_status = rsp->verification_status;

	return err;
}

uint32_t proc_msg_rsp_v2x_fast_mac(void *rsp_buf, void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);
	struct sab_she_fast_mac_rsp *rsp =
		(struct sab_she_fast_mac_rsp *)rsp_buf;

	op_fast_v2x_mac_t *op_args = (op_fast_v2x_mac_t *)args;

	if (GET_STATUS_CODE(rsp->rsp_code) == SAB_FAILURE_STATUS)
		return err;

	if (op_args->flags & SHE_FAST_MAC_FLAGS_VERIFICATION)
		op_args->verification_status = rsp->verification_status;

	return err;
}
