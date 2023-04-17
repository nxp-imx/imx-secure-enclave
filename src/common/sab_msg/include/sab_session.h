// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SAB_SESSION_H
#define SAB_SESSION_H

#include "sab_msg_def.h"

struct sab_cmd_session_open_msg {
	struct sab_mu_hdr hdr;
#ifndef PSA_COMPLIANT
	uint8_t mu_id;
#else
	uint8_t rsv;
#endif
	uint8_t interrupt_idx;
#ifndef PSA_COMPLIANT
	uint8_t tz;
	uint8_t did;
#else
	uint16_t rsv1;
#endif
	uint8_t priority;
	uint8_t operating_mode;
	uint16_t rsv2;
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
