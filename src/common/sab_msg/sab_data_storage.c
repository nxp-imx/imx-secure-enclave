// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <string.h>

#include "internal/hsm_data_storage.h"

#include "sab_data_storage.h"
#include "sab_messaging.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_data_storage(void *phdl,
				  void *cmd_buf, void *rsp_buf,
				  uint32_t *cmd_msg_sz,
				  uint32_t *rsp_msg_sz,
				  uint32_t msg_hdl,
				  void *args)
{
	uint32_t ret = SAB_ENGN_PASS;
	struct sab_cmd_data_storage_msg *cmd =
		(struct sab_cmd_data_storage_msg *) cmd_buf;
	op_data_storage_args_t *op_args = (op_data_storage_args_t *) args;

	if (!op_args)
		return SAB_ENGN_FAIL;

	cmd->data_storage_handle = msg_hdl;
	set_phy_addr_to_words(&cmd->data_address,
			      0u,
			      plat_os_abs_data_buf(phdl,
						   op_args->data,
						   op_args->data_size,
						   (((op_args->flags
						   & HSM_OP_DATA_STORAGE_FLAGS_STORE)
						   == HSM_OP_DATA_STORAGE_FLAGS_STORE)
						   ? DATA_BUF_IS_INPUT : 0u)));
	cmd->data_size = op_args->data_size;
	cmd->data_id = op_args->data_id;
	cmd->flags = op_args->flags;

	*cmd_msg_sz = sizeof(struct sab_cmd_data_storage_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_data_storage_rsp);

	return ret;
}

uint32_t proc_msg_rsp_data_storage(void *rsp_buf, void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);
	op_data_storage_args_t *op_args = (op_data_storage_args_t *)args;
	struct sab_cmd_data_storage_rsp *rsp =
		(struct sab_cmd_data_storage_rsp *)rsp_buf;

#ifdef PSA_COMPLIANT
	if (!op_args) {
		err = SAB_LIB_STATUS(SAB_LIB_RSP_PROC_FAIL);
		goto exit;
	}

	op_args->exp_output_size = rsp->out_data_size;
exit:
#endif

	return err;
}

#if MT_SAB_ENC_DATA_STORAGE
uint32_t prepare_msg_enc_data_storage(void *phdl,
				      void *cmd_buf, void *rsp_buf,
				      uint32_t *cmd_msg_sz,
				      uint32_t *rsp_msg_sz,
				      uint32_t msg_hdl,
				      void *args)
{
	uint32_t ret = SAB_ENGN_PASS;
	struct sab_cmd_enc_data_storage_msg *cmd =
		(struct sab_cmd_enc_data_storage_msg *)cmd_buf;
	op_enc_data_storage_args_t *op_args = (op_enc_data_storage_args_t *)args;

	if (!op_args)
		return SAB_ENGN_FAIL;

	cmd->data_storage_handle = msg_hdl;
	cmd->data_id = op_args->data_id;
	set_phy_addr_to_words(&cmd->data_address,
			      0u,
			      plat_os_abs_data_buf(phdl,
						   op_args->data,
						   op_args->data_size,
						   DATA_BUF_IS_INPUT));
	cmd->data_size = op_args->data_size;
	cmd->enc_algo = op_args->enc_algo;
	cmd->enc_key_id = op_args->enc_key_id;
	cmd->sign_algo = op_args->sign_algo;
	cmd->sign_key_id = op_args->sign_key_id;
	if (!op_args->iv) {
		cmd->iv_address = 0u;
	} else {
		set_phy_addr_to_words(&cmd->iv_address,
				      0u,
				      plat_os_abs_data_buf(phdl,
							   op_args->iv,
							   op_args->iv_size,
							   DATA_BUF_IS_INPUT));
	}
	cmd->iv_size = op_args->iv_size;
	cmd->flags = op_args->flags;
	cmd->lifecycle = op_args->lifecycle;

	*cmd_msg_sz = sizeof(struct sab_cmd_enc_data_storage_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_enc_data_storage_rsp);

	return ret;
}

uint32_t proc_msg_rsp_enc_data_storage(void *rsp_buf, void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);
	op_enc_data_storage_args_t *op_args = (op_enc_data_storage_args_t *)args;
	struct sab_cmd_enc_data_storage_rsp *rsp =
		(struct sab_cmd_enc_data_storage_rsp *)rsp_buf;

	if (!op_args) {
		err = SAB_LIB_STATUS(SAB_LIB_RSP_PROC_FAIL);
		goto exit;
	}

	op_args->out_data_size = rsp->out_data_size;
exit:
	return err;
}
#endif

uint32_t prepare_msg_data_storage_open_req(void *phdl,
					   void *cmd_buf, void *rsp_buf,
					   uint32_t *cmd_msg_sz,
					   uint32_t *rsp_msg_sz,
					   uint32_t msg_hdl,
					   void *args)
{
	uint32_t ret = SAB_ENGN_PASS;
	struct sab_cmd_data_storage_open_msg *cmd =
				 (struct sab_cmd_data_storage_open_msg *) cmd_buf;
	open_svc_data_storage_args_t *op_args = (open_svc_data_storage_args_t *) args;

	if (!op_args)
		return SAB_ENGN_FAIL;

	cmd->key_store_handle = msg_hdl;
	cmd->flags = op_args->flags;

	*cmd_msg_sz = sizeof(struct sab_cmd_data_storage_open_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_data_storage_open_rsp);

	return ret;
}

uint32_t proc_msg_rsp_data_storage_open_req(void *rsp_buf, void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);
	struct sab_cmd_data_storage_open_rsp *rsp =
		(struct sab_cmd_data_storage_open_rsp *) rsp_buf;
	open_svc_data_storage_args_t *op_args = (open_svc_data_storage_args_t *) args;

	if (!op_args) {
		err = SAB_LIB_STATUS(SAB_LIB_RSP_PROC_FAIL);
		goto exit;
	}

	op_args->data_storage_handle = rsp->data_storage_handle;
exit:
	return err;
}

uint32_t prepare_msg_data_storage_close_req(void *phdl,
					    void *cmd_buf, void *rsp_buf,
					    uint32_t *cmd_msg_sz,
					    uint32_t *rsp_msg_sz,
					    uint32_t msg_hdl,
					    void *args)
{
	uint32_t ret = SAB_ENGN_PASS;
	struct sab_cmd_data_storage_close_msg *cmd =
		(struct sab_cmd_data_storage_close_msg *) cmd_buf;

	*cmd_msg_sz = sizeof(struct sab_cmd_data_storage_close_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_data_storage_close_rsp);

	cmd->data_storage_handle = msg_hdl;

	return ret;
}

uint32_t proc_msg_rsp_data_storage_close_req(void *rsp_buf, void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);

	return err;
}
