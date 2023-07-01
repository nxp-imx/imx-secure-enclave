// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SAB_OPEN_UTILS_H
#define SAB_OPEN_UTILS_H

#include <stdint.h>

#include "sab_msg_def.h"

struct sab_cmd_open_utils_msg {
	struct sab_mu_hdr hdr;
	uint32_t key_store_handle;
	uint32_t input_address_ext;
	uint32_t output_address_ext;
};

struct sab_cmd_open_utils_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
	uint32_t utils_handle;
};

uint32_t prepare_msg_open_utils(void *phdl,
				void *cmd_buf, void *rsp_buf,
				uint32_t *cmd_msg_sz,
				uint32_t *rsp_msg_sz,
				uint32_t msg_hdl,
				void *args);

uint32_t proc_msg_rsp_open_utils(void *rsp_buf, void *args);

#endif
