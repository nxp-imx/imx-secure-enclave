// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SAB_ROOT_KEK_EXPORT_H
#define SAB_ROOT_KEK_EXPORT_H

#include <stdint.h>

#include "sab_msg_def.h"

struct sab_root_kek_export_msg {
	struct sab_mu_hdr hdr;
	uint32_t session_handle;
	uint32_t root_kek_address_ext;
	uint32_t root_kek_address;
	uint8_t root_kek_size;
	uint8_t flags;
	uint16_t reserved;
	uint32_t crc;
};

struct sab_root_kek_export_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
};

uint32_t prepare_msg_root_kek_export(void *phdl,
				     void *cmd_buf, void *rsp_buf,
				     uint32_t *cmd_msg_sz,
				     uint32_t *rsp_msg_sz,
				     uint32_t msg_hdl,
				     void *args);

uint32_t proc_msg_rsp_root_kek_export(void *rsp_buf, void *args);
#endif
