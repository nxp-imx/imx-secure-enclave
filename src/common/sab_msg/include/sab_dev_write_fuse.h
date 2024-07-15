// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#ifndef SAB_DEV_WRITE_FUSE_H
#define SAB_DEV_WRITE_FUSE_H

#include "sab_msg_def.h"

struct sab_cmd_dev_write_fuse_msg {
	struct sab_mu_hdr hdr;
	uint16_t bit_pos;
	uint16_t bit_len;
	uint32_t payload1;
	uint32_t payload2;
	uint32_t payload3;
	uint32_t payload4;
	uint32_t crc;
};

struct sab_cmd_dev_write_fuse_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
	uint16_t processed_idx;
	uint16_t reserved;
};

uint32_t prepare_msg_dev_write_fuse(void *phdl, void *cmd_buf, void *rsp_buf,
				    uint32_t *cmd_msg_sz, uint32_t *rsp_msg_sz,
				    uint32_t msg_hdl, void *args);

uint32_t proc_msg_rsp_dev_write_fuse(void *rsp_buf, void *args);

#endif
