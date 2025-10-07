// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include "internal/hsm_asymmetric_crypto.h"

#include "sab_asymmetric_crypto.h"
#include "sab_messaging.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

#ifdef PSA_COMPLIANT
uint32_t prepare_msg_asymmetric_enc_open(void *phdl,
					 void *cmd_buf,
					 void *rsp_buf,
					 uint32_t *cmd_msg_sz,
					 uint32_t *rsp_msg_sz,
					 uint32_t msg_hdl,
					 void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_CMD_MSG_PREP_FAIL);
	struct sab_cmd_asymmetric_enc_open_msg *cmd =
			(struct sab_cmd_asymmetric_enc_open_msg *)cmd_buf;
	op_asymmetric_enc_open_args_t *op_args =
			(op_asymmetric_enc_open_args_t *)args;

	if (!op_args)
		return err;

	cmd->key_store_handle = op_args->key_store_handle;
	cmd->input_pointer_msb = 0;
	cmd->output_pointer_msb = 0;
	cmd->flags = op_args->flags;

	*cmd_msg_sz = sizeof(struct sab_cmd_asymmetric_enc_open_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_asymmetric_enc_open_rsp);

	err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);

	return err;
}

uint32_t proc_msg_rsp_asymmetric_enc_open(void *rsp_buf, void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_RSP_PROC_FAIL);
	struct sab_cmd_asymmetric_enc_open_rsp *rsp =
			(struct sab_cmd_asymmetric_enc_open_rsp *)rsp_buf;
	op_asymmetric_enc_open_args_t *op_args =
			(op_asymmetric_enc_open_args_t *)args;

	if (!op_args)
		return err;

	op_args->asymmetric_enc_handle = rsp->asymmetric_enc_handle;

	err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);

	return err;
}

uint32_t prepare_msg_asymmetric_enc_close(void *phdl,
					  void *cmd_buf,
					  void *rsp_buf,
					  uint32_t *cmd_msg_sz,
					  uint32_t *rsp_msg_sz,
					  uint32_t msg_hdl,
					  void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);
	struct sab_cmd_asymmetric_enc_close_msg *cmd =
			(struct sab_cmd_asymmetric_enc_close_msg *)cmd_buf;

	cmd->asymmetric_enc_handle = msg_hdl;

	*cmd_msg_sz = sizeof(struct sab_cmd_asymmetric_enc_close_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_asymmetric_enc_close_rsp);

	return err;
}

uint32_t proc_msg_rsp_asymmetric_enc_close(void *rsp_buf, void *args)
{
	return SAB_LIB_STATUS(SAB_LIB_SUCCESS);
}

uint32_t prepare_msg_asymmetric_enc(void *phdl,
				    void *cmd_buf,
				    void *rsp_buf,
				    uint32_t *cmd_msg_sz,
				    uint32_t *rsp_msg_sz,
				    uint32_t msg_hdl,
				    void *args)
{
	uint64_t phy_addr = 0;
	uint32_t ret = 0;
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_CMD_MSG_PREP_FAIL);
	struct sab_cmd_asymmetric_enc_msg *cmd =
			(struct sab_cmd_asymmetric_enc_msg *)cmd_buf;
	op_asymmetric_enc_args_t *op_args =
			(op_asymmetric_enc_args_t *)args;

	if (!op_args)
		return err;

	cmd->asymmetric_enc_handle = op_args->asymmetric_enc_handle;
	cmd->flags = op_args->flags;
	cmd->algorithm = op_args->algorithm;

	/**
	 * Map plaintext data address.
	 * not putting check on size because
	 * For decryption operation, plaintext size can’t be known in
	 * advance by EdgeLock Secure Enclave Firmware. Output plaintext
	 * size is then checked after the operation completion.
	 * Setting an invalid size (smaller than expected) will result in
	 * 0x1D29 error and expected size will be returned.
	 * To avoid useless resource consumption, operation can be called
	 * with output plaintext size set to 0. In that case, 0x1D29 error
	 * is still observed but maximum plaintext size is returned.
	 */
	cmd->plaintext_size = op_args->plaintext_size;
	ret = plat_os_abs_data_buf_v2((struct plat_os_abs_hdl *)phdl,
				      &phy_addr,
				      op_args->plaintext_addr,
				      op_args->plaintext_size,
				      DATA_BUF_IS_IN_OUT);
	if (ret != PLAT_SUCCESS) {
		err |= ret;
		return err;
	}

	set_phy_addr_to_words(&cmd->plaintext_addr,
			      0u,
			      phy_addr);

	if (cmd->flags & HSM_ASYM_FLAGS_PLAINTEXT_KEY) {
		cmd->input_plainkey_size = op_args->input_plainkey_size;
		cmd->input_plainkey_type = op_args->input_plainkey_type;
		cmd->input_plainkey_security_size =
			op_args->input_plainkey_security_size;
		/* Map plain key address */
		ret = plat_os_abs_data_buf_v2((struct plat_os_abs_hdl *)phdl,
					      &phy_addr,
					      op_args->key_addr,
					      cmd->input_plainkey_size,
					      DATA_BUF_IS_INPUT);
		if (ret != PLAT_SUCCESS) {
			err |= ret;
			return err;
		}

		set_phy_addr_to_words(&cmd->key_id_addr,
				      0u,
				      phy_addr);

	} else {
		cmd->key_id_addr = op_args->key_id;
	}

	/* Map cipher text address */
	cmd->ciphertext_size = op_args->ciphertext_size;

	ret = plat_os_abs_data_buf_v2((struct plat_os_abs_hdl *)phdl,
				      &phy_addr,
				      op_args->ciphertext_addr,
				      op_args->ciphertext_size,
				      DATA_BUF_IS_IN_OUT);
	if (ret != PLAT_SUCCESS) {
		err |= ret;
		return err;
	}

	set_phy_addr_to_words(&cmd->ciphertext_addr,
			      0u,
			      phy_addr);

	/* Map label address */
	if (op_args->label_size != 0) {
		cmd->label_size = op_args->label_size;
		ret = plat_os_abs_data_buf_v2((struct plat_os_abs_hdl *)phdl,
					      &phy_addr,
					      op_args->label_addr,
					      op_args->label_size,
					      DATA_BUF_IS_INPUT);
		if (ret != PLAT_SUCCESS) {
			err |= ret;
			return err;
		}

		set_phy_addr_to_words(&cmd->label_addr,
				      0u,
				      phy_addr);
	}

	*cmd_msg_sz = sizeof(struct sab_cmd_asymmetric_enc_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_asymmetric_enc_rsp);

	err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);

	return err;
}

uint32_t proc_msg_rsp_asymmetric_enc(void *rsp_buf, void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);
	struct sab_cmd_asymmetric_enc_rsp *rsp =
			(struct sab_cmd_asymmetric_enc_rsp *)rsp_buf;
	op_asymmetric_enc_args_t *op_args =
			(op_asymmetric_enc_args_t *)args;

	if (!op_args)
		return SAB_LIB_STATUS(SAB_LIB_RSP_PROC_FAIL);

	if (op_args->flags == HSM_ASYM_FLAGS_ENCRYPT)
		op_args->exp_ciphertext_size = rsp->output_size;
	else
		op_args->exp_plaintext_size = rsp->output_size;

	return err;
}
#endif
