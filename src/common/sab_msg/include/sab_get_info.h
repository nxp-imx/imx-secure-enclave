// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SAB_GET_INFO_H
#define SAB_GET_INFO_H

#include "sab_msg_def.h"

#ifdef PSA_COMPLIANT
#define CHIP_UNIQUE_ID_SZ        16
#else
#define CHIP_UNIQUE_ID_SZ        8
#endif

struct sab_cmd_get_info_msg {
	struct sab_mu_hdr hdr;
	uint32_t session_handle;
};

struct sab_cmd_get_info_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
	uint32_t user_sab_id;
	uint8_t uid[CHIP_UNIQUE_ID_SZ];
	uint16_t monotonic_counter;
	uint16_t lifecycle;
	uint32_t version;
	uint32_t version_ext;
	uint8_t  fips_mode;
	uint8_t  rsv[3];
	uint32_t crc;
};

uint32_t prepare_msg_get_info(void *phdl, void *cmd_buf, void *rsp_buf,
			      uint32_t *cmd_msg_sz, uint32_t *rsp_msg_sz,
			      uint32_t msg_hdl, void *args);

uint32_t proc_msg_rsp_get_info(void *rsp_buf, void *args);
#endif
