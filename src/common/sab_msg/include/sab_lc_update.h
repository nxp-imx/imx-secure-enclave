/*
 * Copyright 2023 NXP
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
