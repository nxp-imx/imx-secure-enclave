// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#ifndef SAB_DEV_MONO_COUNTER_H
#define SAB_DEV_MONO_COUNTER_H

#include "sab_msg_def.h"

struct sab_cmd_dev_mono_counter_msg {
	struct sab_mu_hdr hdr;
	uint8_t ele_hsm_fuse_word;
	uint8_t v2x_hsm_fuse_word;
	uint8_t v2x_she_fuse_word;
	uint8_t reserved;
};

struct sab_cmd_dev_mono_counter_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
	uint8_t ele_hsm_fuse_word;
	uint8_t v2x_hsm_fuse_word;
	uint8_t v2x_she_fuse_word;
	uint8_t reserved;
};

uint32_t prepare_msg_dev_mono_counter(void *phdl, void *cmd_buf, void *rsp_buf,
				      uint32_t *cmd_msg_sz, uint32_t *rsp_msg_sz,
				      uint32_t msg_hdl, void *args);

uint32_t proc_msg_rsp_dev_mono_counter(void *rsp_buf, void *args);

#endif
