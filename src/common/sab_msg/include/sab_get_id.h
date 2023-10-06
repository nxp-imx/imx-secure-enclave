// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SAB_GET_ID_H
#define SAB_GET_ID_H

#include <internal/she_get_id.h>
#include "sab_msg_def.h"

struct sab_cmd_get_id_msg {
	struct sab_mu_hdr hdr;
	uint32_t she_utils_handle;
	uint8_t challenge[SHE_CHALLENGE_SIZE];
	uint32_t crc;
};

struct sab_cmd_get_id_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
	uint8_t id[SHE_ID_SIZE];
	uint8_t sreg;
	uint8_t mac[SHE_MAC_SIZE];
	uint32_t crc;
};

uint32_t prepare_msg_get_id(void *phdl, void *cmd_buf, void *rsp_buf,
			    uint32_t *cmd_msg_sz, uint32_t *rsp_msg_sz,
			    uint32_t msg_hdl, void *args);

uint32_t proc_msg_rsp_get_id(void *rsp_buf, void *args);
#endif
