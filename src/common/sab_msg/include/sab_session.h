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

#ifndef SAB_SESSION_H
#define SAB_SESSION_H

#include "sab_msg_def.h"

struct sab_cmd_session_open_msg {
	struct sab_mu_hdr hdr;
	uint8_t mu_id;
	uint8_t interrupt_idx;
	uint8_t tz;
	uint8_t did;
	uint8_t priority;
	uint8_t operating_mode;
	uint16_t pad;
};

struct sab_cmd_session_open_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
	uint32_t session_handle;
};

struct sab_cmd_session_close_msg {
	struct sab_mu_hdr hdr;
	uint32_t session_handle;
};

struct sab_cmd_session_close_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
};

uint32_t prepare_msg_session_open_req(void *phdl,
				      void *cmd_buf, void *rsp_buf,
				      uint32_t *cmd_msg_sz,
				      uint32_t *rsp_msg_sz,
				      uint32_t msg_hdl,
				      void *args);

uint32_t proc_msg_rsp_session_open_req(void *rsp_buf, void *args);

uint32_t prepare_msg_session_close_req(void *phdl,
				       void *cmd_buf, void *rsp_buf,
				       uint32_t *cmd_msg_sz,
				       uint32_t *rsp_msg_sz,
				       uint32_t msg_hdl,
				       void *args);

uint32_t proc_msg_rsp_session_close_req(void *rsp_buf, void *args);

#endif
