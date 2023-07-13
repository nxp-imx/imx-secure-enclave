// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SAB_GET_STATUS_H
#define SAB_GET_STATUS_H

#include <stdint.h>

#include "sab_msg_def.h"

struct sab_cmd_get_status_msg {
	struct sab_mu_hdr hdr;
	uint32_t utils_handle;
};

struct sab_cmd_get_status_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
	uint8_t sreg;
	uint8_t pad[3];
};

uint32_t prepare_msg_get_status(void *phdl,
				void *cmd_buf, void *rsp_buf,
				uint32_t *cmd_msg_sz,
				uint32_t *rsp_msg_sz,
				uint32_t msg_hdl,
				void *args);

uint32_t proc_msg_rsp_get_status(void *rsp_buf, void *args);

#endif
