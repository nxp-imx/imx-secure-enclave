// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#ifndef SAB_BLOB_UNBLOB_H
#define SAB_BLOB_UNBLOB_H

#include "sab_msg_def.h"

#define MAX_NUM_EVENT_REPORT	8

struct rom_cmd_blob_unblob_msg {
	struct sab_mu_hdr hdr;
	uint32_t in_msb_addr;
	uint32_t in_lsb_addr;
	uint32_t out_msb_addr;
	uint32_t out_lsb_addr;
	uint32_t usr_ctx_msb_addr;
	uint32_t usr_ctx_lsb_addr;
	uint32_t in_size;
	uint32_t out_size;
	uint32_t usr_ctx_size;
	uint8_t flags;
	uint8_t res[2];
	uint8_t mode;
	uint32_t crc;
};

struct rom_cmd_blob_unblob_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
	uint32_t out_size;
};

uint32_t proc_msg_rsp_blob_unblob(void *rsp_buf, void *args);
uint32_t prepare_msg_blob_unblob(void *phdl, void *cmd_buf, void *rsp_buf,
				 uint32_t *cmd_msg_sz, uint32_t *rsp_msg_sz,
				 uint32_t msg_hdl, void *args);
#endif
