// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include "string.h"

#include "internal/hsm_debug_dump.h"

#include "sab_debug_dump.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_debugdump(void *phdl,
			       void *cmd_buf, void *rsp_buf,
			       uint32_t *cmd_msg_sz,
			       uint32_t *rsp_msg_sz,
			       uint32_t msg_hdl,
			       void *args)
{
	uint32_t ret = SAB_ENGN_PASS;
	struct rom_cmd_firmware_dump_cmd *cmd =
		(struct rom_cmd_firmware_dump_cmd *) cmd_buf;

	/* Send the keys store open command to platform. */
	cmd->hdr.ver = 0x06;
	cmd->hdr.size = 0x01;
	cmd->hdr.command = 0x21;
	cmd->hdr.tag = 0x17;
	*cmd_msg_sz = sizeof(struct rom_cmd_firmware_dump_cmd);
	*rsp_msg_sz = sizeof(struct rom_cmd_firmware_dump_rsp);

	return ret;
}

uint32_t proc_msg_rsp_debugdump(void *rsp_buf, void *args)
{
	struct rom_cmd_firmware_dump_rsp *rsp =
		(struct rom_cmd_firmware_dump_rsp *) rsp_buf;
	op_debug_dump_args_t *op_args = (op_debug_dump_args_t *) args;

	if (!op_args)
		return SAB_FAILURE_STATUS;

	/* 1 word for header
	 * 2 word for rsp_code
	 * 3 word for CRC
	 */

	/*
	 * safe-check. Added check on size as memory op (memcpy) going to use it.
	 */
	if ((rsp->hdr.size <= ROM_BUF_DUMP_HDR_MIN_SIZE) ||
		(rsp->hdr.size > (ROM_BUF_DUMP_MAX_WSIZE + 3)))
		return SAB_FAILURE_STATUS;

	op_args->dump_buf_len = rsp->hdr.size - 3;

	plat_os_abs_memcpy((uint8_t *)op_args->dump_buf,
			   (uint8_t *)rsp->buffer,
			   op_args->dump_buf_len * sizeof(uint32_t));

	if (op_args->dump_buf_len ==  ROM_BUF_DUMP_MAX_WSIZE) {
		op_args->is_dump_pending = true;
	} else {
		op_args->is_dump_pending = false;
	}

	return SAB_SUCCESS_STATUS;
}
