// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "internal/hsm_dev_write_fuse.h"

#include "sab_dev_write_fuse.h"
#include "sab_messaging.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_dev_write_fuse(void *phdl, void *cmd_buf, void *rsp_buf,
				    uint32_t *cmd_msg_sz, uint32_t *rsp_msg_sz,
				    uint32_t msg_hdl, void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_CMD_MSG_PREP_FAIL);
	uint32_t payload_length_bytes = 0;
	struct sab_cmd_dev_write_fuse_msg *cmd =
		(struct sab_cmd_dev_write_fuse_msg *)cmd_buf;
	op_dev_write_fuse_args_t *op_args = (op_dev_write_fuse_args_t *)args;

	cmd->bit_pos = TO_UINT16_T(op_args->word_pos * BITS_IN_WORD + op_args->bit_pos);
	cmd->bit_len = op_args->bit_len;

	if (cmd->bit_len < BITS_IN_WORD)
		payload_length_bytes = 4;
	else
		payload_length_bytes = cmd->bit_len / 8;

	plat_os_abs_memcpy((uint8_t *)cmd->payload,
			   (uint8_t *)op_args->payload,
			   payload_length_bytes);

	*rsp_msg_sz = sizeof(struct sab_cmd_dev_write_fuse_rsp);
	if (payload_length_bytes > 4) //greater than one word, then add CRC word
		*cmd_msg_sz = sizeof(struct sab_cmd_dev_write_fuse_msg) +
			      payload_length_bytes +
			      sizeof(uint32_t); //CRC
	else
		*cmd_msg_sz = sizeof(struct sab_cmd_dev_write_fuse_msg) +
			      payload_length_bytes;

	err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);

	return err;
}

uint32_t proc_msg_rsp_dev_write_fuse(void *rsp_buf, void *args)
{
	op_dev_write_fuse_args_t *op_args = (op_dev_write_fuse_args_t *)args;
	struct sab_cmd_dev_write_fuse_rsp *rsp =
		(struct sab_cmd_dev_write_fuse_rsp *)rsp_buf;

	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);

	if (GET_STATUS_CODE(rsp->rsp_code) == SAB_FAILURE_STATUS)
		return err;

	op_args->processed_idx = rsp->processed_idx;

	return err;
}
