// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#include "common/key_store.h"

#include "sab_messaging.h"
#include "sab_key_store.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_key_store_open_req(void *phdl,
					void *cmd_buf, void *rsp_buf,
					uint32_t *cmd_msg_sz,
					uint32_t *rsp_msg_sz,
					uint32_t msg_hdl,
					void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_CMD_MSG_PREP_FAIL);
	struct sab_cmd_key_store_open_msg *cmd =
		(struct sab_cmd_key_store_open_msg *)cmd_buf;
	open_svc_key_store_args_t *op_args =
		(open_svc_key_store_args_t *)args;

	if (!op_args)
		goto exit;

	cmd->session_handle = msg_hdl;
	cmd->key_store_id = op_args->key_store_identifier;
	cmd->password = op_args->authentication_nonce;
	cmd->flags = op_args->flags;
#ifndef PSA_COMPLIANT
	cmd->max_updates = op_args->max_updates_number;
	cmd->min_mac_length = op_args->min_mac_length;
#endif

	*cmd_msg_sz = sizeof(struct sab_cmd_key_store_open_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_key_store_open_rsp);

	err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);
exit:
	return err;
}

uint32_t proc_msg_rsp_key_store_open_req(void *rsp_buf, void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_RSP_PROC_FAIL);
	struct sab_cmd_key_store_open_rsp *rsp =
		(struct sab_cmd_key_store_open_rsp *)rsp_buf;
	open_svc_key_store_args_t *op_args =
		(open_svc_key_store_args_t *)args;

	if (!op_args)
		goto exit;

	op_args->key_store_hdl = rsp->key_store_handle;

	err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);
exit:
	return err;
}

uint32_t prepare_msg_key_store_close_req(void *phdl,
					 void *cmd_buf, void *rsp_buf,
					 uint32_t *cmd_msg_sz,
					 uint32_t *rsp_msg_sz,
					 uint32_t msg_hdl,
					 void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);
	struct sab_cmd_key_store_close_msg *cmd =
		(struct sab_cmd_key_store_close_msg *)cmd_buf;

	cmd->key_store_handle = msg_hdl;

	*cmd_msg_sz = sizeof(struct sab_cmd_key_store_close_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_key_store_close_rsp);

	return err;
}

uint32_t proc_msg_rsp_key_store_close_req(void *rsp_buf, void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);

	return err;
}

#if MT_SAB_KEY_STORE_REPROV_EN
uint32_t prepare_msg_key_store_reprov_en_req(void *phdl,
					     void *cmd_buf, void *rsp_buf,
					     uint32_t *cmd_msg_sz,
					     uint32_t *rsp_msg_sz,
					     uint32_t msg_hdl,
					     void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_CMD_MSG_PREP_FAIL);
	struct sab_cmd_key_store_reprov_en_msg *cmd =
		(struct sab_cmd_key_store_reprov_en_msg *)cmd_buf;
	op_key_store_reprov_en_args_t *op_args =
		(op_key_store_reprov_en_args_t *)args;
	uint64_t phy_addr = 0;
	uint32_t ret;

	if (!op_args)
		goto exit;

	cmd->signed_msg_msb_addr = 0u;
	ret = plat_os_abs_data_buf_v2((struct plat_os_abs_hdl *)phdl,
				      &phy_addr,
				      op_args->signed_message,
				      op_args->signed_msg_size,
				      DATA_BUF_IS_INPUT);
	if (ret != PLAT_SUCCESS) {
		err |= ret;
		goto exit;
	}

	set_phy_addr_to_words(&cmd->signed_msg_lsb_addr,
			      0u,
			      phy_addr);

	*cmd_msg_sz = sizeof(struct sab_cmd_key_store_reprov_en_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_key_store_reprov_en_rsp);

	err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);
exit:
	return err;
}

uint32_t proc_msg_rsp_key_store_reprov_en_req(void *rsp_buf, void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);

	return err;
}
#endif
