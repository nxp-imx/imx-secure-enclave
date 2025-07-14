// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#ifndef SAB_GET_EVENT_H
#define SAB_GET_EVENT_H

#include "internal/hsm_get_event.h"
#include "sab_msg_def.h"

struct rom_cmd_get_event_msg {
	struct sab_mu_hdr hdr;
};

struct rom_cmd_get_event_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
	uint16_t event_count;
	uint16_t event_max;
	uint32_t event_info[MAX_NUM_EVENT_REPORT];
	uint32_t crc;
};

uint32_t proc_msg_rsp_get_event(void *rsp_buf, void *args);
uint32_t prepare_msg_get_event(void *phdl, void *cmd_buf, void *rsp_buf,
			       uint32_t *cmd_msg_sz, uint32_t *rsp_msg_sz,
			       uint32_t msg_hdl, void *args);
#endif
