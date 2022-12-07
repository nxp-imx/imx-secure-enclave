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

#ifndef SAB_DEBUG_DUMP_H
#define SAB_DEBUG_DUMP_H

#include "stdint.h"
#include "sab_msg_def.h"

#define ROM_BUF_DUMP_HDR_MIN_SIZE 3u
#define ROM_BUF_DUMP_MAX_WSIZE 20U

struct rom_cmd_firmware_dump_cmd {
	struct sab_mu_hdr hdr;
};

struct rom_cmd_firmware_dump_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
	uint32_t buffer[ROM_BUF_DUMP_MAX_WSIZE];
	uint32_t crc;
};

uint32_t proc_msg_rsp_debugdump(void *rsp_buf, void *args);
uint32_t prepare_msg_debugdump(void *phdl,
			       void *cmd_buf, void *rsp_buf,
			       uint32_t *cmd_msg_sz,
			       uint32_t *rsp_msg_sz,
			       uint32_t msg_hdl,
			       void *args);
#endif
