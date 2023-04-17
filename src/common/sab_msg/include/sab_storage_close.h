// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SAB_STORAGE_CLOSE_H
#define SAB_STORAGE_CLOSE_H

#include "sab_msg_def.h"

struct sab_cmd_storage_close_msg {
	struct sab_mu_hdr hdr;
	uint32_t storage_handle;
};

struct sab_cmd_storage_close_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
};

uint32_t prepare_msg_storage_close(void *phdl,
				   void *cmd_buf, void *rsp_buf,
				   uint32_t *cmd_msg_sz,
				   uint32_t *rsp_msg_sz,
				   uint32_t msg_hdl,
				   void *args);

uint32_t proc_msg_rsp_storage_close(void *rsp_buf, void *args);
#endif
