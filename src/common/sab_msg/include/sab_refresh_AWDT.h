// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#ifndef SAB_REFRESH_AWDT_H
#define SAB_REFRESH_AWDT_H

#include "sab_msg_def.h"

struct sab_cmd_refresh_AWDT_msg {
	struct sab_mu_hdr hdr;
	uint8_t  timer_id;
	uint8_t  pub_key_index;
	uint16_t reserved1;
	uint32_t req_data_addr;
	uint32_t req_data_size;
};

struct sab_cmd_refresh_AWDT_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
};

uint32_t prepare_msg_refresh_AWDT(void *phdl, void *cmd_buf, void *rsp_buf,
				  uint32_t *cmd_msg_sz, uint32_t *rsp_msg_sz,
				  uint32_t msg_hdl, void *args);

uint32_t proc_msg_rsp_refresh_AWDT(void *rsp_buf, void *args);

#endif
