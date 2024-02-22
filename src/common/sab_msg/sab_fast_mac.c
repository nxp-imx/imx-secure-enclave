// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#include "sab_messaging.h"
#include "sab_fast_mac.h"
#include "internal/she_fast_mac.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

static uint32_t process_verify_args(void *phdl,
				    struct sab_she_fast_mac_msg *cmd,
				    void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_CMD_MSG_PREP_FAIL);
	uint32_t ret;
	uint64_t temp;
	op_verify_mac_t *op_args = (op_verify_mac_t *)args;

	cmd->key_id = op_args->key_ext | op_args->key_id;
	cmd->data_length = op_args->message_length;
	cmd->mac_length = op_args->mac_length;
	cmd->flags = op_args->flags;

	/*
	 * the MAC data is stored right after the input data
	 */
	if (op_args->message_length == 0u) {
		ret = plat_os_abs_data_buf_v2((struct plat_os_abs_hdl *)phdl,
					      &temp,
					      op_args->mac,
					      SHE_MAC_SIZE,
					      DATA_BUF_IS_INPUT |
					      DATA_BUF_USE_SEC_MEM |
					      DATA_BUF_SHORT_ADDR);
		cmd->data_offset = temp & SEC_MEM_SHORT_ADDR_MASK;
	} else {
		ret = plat_os_abs_data_buf_v2((struct plat_os_abs_hdl *)phdl,
					      &temp,
					      op_args->message,
					      op_args->message_length,
					      DATA_BUF_IS_INPUT |
					      DATA_BUF_USE_SEC_MEM |
					      DATA_BUF_SHORT_ADDR);
		if (ret != PLAT_SUCCESS) {
			err |= ret;
			return err;
		}

		cmd->data_offset = temp & SEC_MEM_SHORT_ADDR_MASK;

		ret = plat_os_abs_data_buf_v2((struct plat_os_abs_hdl *)phdl,
					      &temp,
					      op_args->mac,
					      SHE_MAC_SIZE,
					      DATA_BUF_IS_INPUT |
					      DATA_BUF_USE_SEC_MEM |
					      DATA_BUF_SHORT_ADDR);
	}

	if (ret != PLAT_SUCCESS) {
		err |= ret;
		return err;
	}

	return SAB_LIB_STATUS(SAB_LIB_SUCCESS);
}

static uint32_t process_generate_args(void *phdl,
				      struct sab_she_fast_mac_msg *cmd,
				      void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_CMD_MSG_PREP_FAIL);
	uint32_t ret;
	uint64_t temp;
	op_generate_mac_t *op_args = (op_generate_mac_t *)args;

	cmd->key_id = op_args->key_ext | op_args->key_id;
	cmd->data_length = op_args->message_length;
	cmd->mac_length = 0u;
	cmd->flags = op_args->flags;

	/*
	 * the MAC data is stored right after the input data
	 */
	if (op_args->message_length == 0u) {
		ret = plat_os_abs_data_buf_v2((struct plat_os_abs_hdl *)phdl,
					      &temp,
					      op_args->mac,
					      SHE_MAC_SIZE,
					      DATA_BUF_USE_SEC_MEM |
					      DATA_BUF_SHORT_ADDR);
		cmd->data_offset = temp & SEC_MEM_SHORT_ADDR_MASK;
	} else {
		ret = plat_os_abs_data_buf_v2((struct plat_os_abs_hdl *)phdl,
					      &temp,
					      op_args->message,
					      op_args->message_length,
					      DATA_BUF_IS_INPUT |
					      DATA_BUF_USE_SEC_MEM |
					      DATA_BUF_SHORT_ADDR);
		if (ret != PLAT_SUCCESS) {
			err |= ret;
			return err;
		}

		cmd->data_offset = temp & SEC_MEM_SHORT_ADDR_MASK;

		ret = plat_os_abs_data_buf_v2((struct plat_os_abs_hdl *)phdl,
					      &temp,
					      op_args->mac,
					      SHE_MAC_SIZE,
					      DATA_BUF_USE_SEC_MEM |
					      DATA_BUF_SHORT_ADDR);
	}

	if (ret != PLAT_SUCCESS) {
		err |= ret;
		return err;
	}

	return SAB_LIB_STATUS(SAB_LIB_SUCCESS);
}

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
	op_generate_mac_t *op_args = (op_generate_mac_t *)args;

	cmd->utils_handle = msg_hdl;

	/* Variable 'flags', is the first member in both the
	 * structures: op_generate_mac_t & op_verify_mac_t
	 */
	if (op_args->flags & SHE_FAST_MAC_FLAGS_VERIFICATION)
		err = process_verify_args(phdl, cmd, args);
	else
		err = process_generate_args(phdl, cmd, args);

	*cmd_msg_sz = sizeof(struct sab_she_fast_mac_msg);
	*rsp_msg_sz = sizeof(struct sab_she_fast_mac_rsp);

	return err;
}

uint32_t proc_msg_rsp_fast_mac(void *rsp_buf, void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);
	struct sab_she_fast_mac_rsp *rsp =
		(struct sab_she_fast_mac_rsp *)rsp_buf;

	op_verify_mac_t *op_args = (op_verify_mac_t *)args;

	if (GET_STATUS_CODE(rsp->rsp_code) == SAB_FAILURE_STATUS)
		return err;

	if (op_args->flags & SHE_FAST_MAC_FLAGS_VERIFICATION)
		op_args->verification_status = rsp->verification_status;

	return err;
}
