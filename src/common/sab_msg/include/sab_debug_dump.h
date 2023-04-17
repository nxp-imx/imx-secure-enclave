// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022 NXP
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
