// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SAB_SHARED_BUF_H
#define SAB_SHARED_BUF_H

#include <stdint.h>

#include "sab_msg_def.h"

struct sab_cmd_shared_buf_msg {
	struct sab_mu_hdr hdr;
	uint32_t session_handle;
};

struct sab_cmd_shared_buf_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
	uint16_t shared_buf_offset;
	uint16_t shared_buf_size;
};

uint32_t prepare_msg_shared_buf(void *phdl,
				void *cmd_buf, void *rsp_buf,
				uint32_t *cmd_msg_sz,
				uint32_t *rsp_msg_sz,
				uint32_t msg_hdl,
				void *args);

uint32_t proc_msg_rsp_shared_buf(void *rsp_buf, void *args);

#endif
