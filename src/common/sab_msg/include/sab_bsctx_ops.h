// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#ifndef SAB_BOOT_STAGE_CTX_OPS_H
#define SAB_BOOT_STAGE_CTX_OPS_H

#include "sab_msg_def.h"

struct rom_cmd_bsctx_ops_msg {
	struct sab_mu_hdr hdr;
	uint8_t op_code;
	uint8_t res[3];
	uint32_t bs_ctx_val;
};

struct rom_cmd_bsctx_ops_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
	uint32_t bs_ctx_val;
};

uint32_t proc_msg_rsp_bsctx_ops(void *rsp_buf, void *args);
uint32_t prepare_msg_bsctx_ops(void *phdl, void *cmd_buf, void *rsp_buf,
			       uint32_t *cmd_msg_sz, uint32_t *rsp_msg_sz,
			       uint32_t msg_hdl, void *args);
#endif
