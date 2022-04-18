/*
 * Copyright 2022 NXP
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
	uint32_t ret = 0;
	struct rom_cmd_firmware_dump_cmd *cmd =
		(struct rom_cmd_firmware_dump_cmd *) cmd_buf;
	struct rom_cmd_firmware_dump_rsp *rsp =
		(struct rom_cmd_firmware_dump_rsp *) rsp_buf;

	int32_t error = 1;
	int i = 0;
	int buf_len = 0;

	/* Send the keys store open command to platform. */
	cmd->hdr.ver = 0x06;
	cmd->hdr.size = 0x01;
	cmd->hdr.command = 0x21;
	cmd->hdr.tag = 0x17;
	*cmd_msg_sz = sizeof(struct rom_cmd_firmware_dump_cmd);
	*rsp_msg_sz = sizeof(struct rom_cmd_firmware_dump_rsp);

	return 0;
}

uint32_t proc_msg_rsp_debugdump(void *rsp_buf, void *args)
{
	struct rom_cmd_firmware_dump_rsp *rsp =
		(struct rom_cmd_firmware_dump_rsp *) rsp_buf;
	op_debug_dump_args_t *op_args = (op_debug_dump_args_t *) args;

	op_args->dump_buf_len = rsp->hdr.size - 3;

	memcpy(op_args->dump_buf, rsp->buffer, op_args->dump_buf_len);

	if (op_args->dump_buf_len ==  ROM_BUF_DUMP_MAX_WSIZE) {
		op_args->is_dump_pending = true;
	} else {
		op_args->is_dump_pending = false;
	}

	return SAB_SUCCESS_STATUS;
}
