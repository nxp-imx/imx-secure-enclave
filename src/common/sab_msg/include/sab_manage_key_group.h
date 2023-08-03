// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SAB_MANAGE_KEY_GROUP_H
#define SAB_MANAGE_KEY_GROUP_H

#include <stdint.h>

#include "sab_msg_def.h"

struct sab_cmd_manage_key_group_msg {
	struct sab_mu_hdr hdr;
	uint32_t key_management_handle;
	uint16_t key_group;
	uint8_t flags;
	uint8_t rsv;
};

struct sab_cmd_manage_key_group_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
};

uint32_t prepare_msg_manage_key_group(void *phdl,
				      void *cmd_buf, void *rsp_buf,
				      uint32_t *cmd_msg_sz,
				      uint32_t *rsp_msg_sz,
				      uint32_t msg_hdl,
				      void *args);

uint32_t proc_msg_rsp_manage_key_group(void *rsp_buf, void *args);
#endif
