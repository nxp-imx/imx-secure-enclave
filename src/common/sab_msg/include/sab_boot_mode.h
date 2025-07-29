// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#ifndef SAB_BOOT_MODE_H
#define SAB_BOOT_MODE_H

#include "sab_msg_def.h"

struct sab_cmd_get_boot_mode_msg {
	struct sab_mu_hdr hdr;
	uint32_t reserved;
};

struct sab_cmd_get_boot_mode_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
	uint8_t  boot_mode;
	uint8_t  timer_id;
	uint16_t reserved;
};

struct sab_cmd_set_boot_mode_msg {
	struct sab_mu_hdr hdr;
	uint8_t new_boot_mode;
	uint8_t reserved;
	uint16_t reserved1;
};

struct sab_cmd_set_boot_mode_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
	uint8_t stored_boot_mode;
	uint8_t reserved;
	uint16_t reserved1;
};

uint32_t prepare_msg_get_boot_mode(void *phdl, void *cmd_buf, void *rsp_buf,
				   uint32_t *cmd_msg_sz, uint32_t *rsp_msg_sz,
				   uint32_t msg_hdl, void *args);

uint32_t proc_msg_rsp_get_boot_mode(void *rsp_buf, void *args);

uint32_t prepare_msg_set_boot_mode(void *phdl, void *cmd_buf, void *rsp_buf,
				   uint32_t *cmd_msg_sz, uint32_t *rsp_msg_sz,
				   uint32_t msg_hdl, void *args);

uint32_t proc_msg_rsp_set_boot_mode(void *rsp_buf, void *args);
#endif
