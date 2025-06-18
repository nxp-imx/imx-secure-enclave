// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#ifndef SAB_GET_NONCE_H
#define SAB_GET_NONCE_H

#include "sab_msg_def.h"

struct sab_cmd_get_nonce_msg {
	struct sab_mu_hdr hdr;
	uint8_t  timer_id;
	uint8_t  reserved;
	uint16_t reserved1;
	uint32_t addr;
	uint32_t input_size;
};

struct sab_cmd_get_nonce_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
	uint32_t output_size;
};

uint32_t prepare_msg_get_nonce(void *phdl, void *cmd_buf, void *rsp_buf,
			       uint32_t *cmd_msg_sz, uint32_t *rsp_msg_sz,
			       uint32_t msg_hdl, void *args);

uint32_t proc_msg_rsp_get_nonce(void *rsp_buf, void *args);

#endif
