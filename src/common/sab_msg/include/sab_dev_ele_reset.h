// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#ifndef SAB_DEV_ELE_RESET_H
#define SAB_DEV_ELE_RESET_H

#include "sab_msg_def.h"

struct sab_cmd_dev_ele_reset_msg {
	struct sab_mu_hdr hdr;
};

struct sab_cmd_dev_ele_reset_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
};

uint32_t prepare_msg_dev_ele_reset(void *phdl, void *cmd_buf, void *rsp_buf,
				   uint32_t *cmd_msg_sz, uint32_t *rsp_msg_sz,
				   uint32_t msg_hdl, void *args);

uint32_t proc_msg_rsp_dev_ele_reset(void *rsp_buf, void *args);

#endif
