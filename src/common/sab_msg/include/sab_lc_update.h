// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SAB_LCYCLE_MGMT_H
#define SAB_LCYCLE_MGMT_H

#include "sab_msg_def.h"

struct rom_cmd_lc_update_msg {
	struct sab_mu_hdr hdr;
	uint16_t new_lc_state;
	uint16_t rsv;
};

struct rom_cmd_lc_update_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
};

uint32_t proc_msg_rsp_fwd_lc_update(void *rsp_buf, void *args);
uint32_t prepare_msg_fwd_lc_update(void *phdl,
				   void *cmd_buf, void *rsp_buf,
				   uint32_t *cmd_msg_sz,
				   uint32_t *rsp_msg_sz,
				   uint32_t msg_hdl,
				   void *args);

uint32_t proc_msg_rsp_ret_lc_update(void *rsp_buf, void *args);
uint32_t prepare_msg_ret_lc_update(void *phdl,
				   void *cmd_buf, void *rsp_buf,
				   uint32_t *cmd_msg_sz,
				   uint32_t *rsp_msg_sz,
				   uint32_t msg_hdl,
				   void *args);
#endif
