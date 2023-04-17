// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SAB_GET_KEY_ATTR_H
#define SAB_GET_KEY_ATTR_H

#include <stdint.h>

#include "sab_msg_def.h"

struct sab_cmd_get_key_attr_msg {
	struct sab_mu_hdr hdr;//(see Table 18)
	uint32_t key_management_hdl;
	uint32_t key_identifier;
	uint32_t rsv;
};

struct sab_cmd_get_key_attr_rsp {
	struct sab_mu_hdr hdr;//(see Table 18)
	uint32_t rsp_code;
	uint16_t size_bits;
	uint16_t type;
	uint32_t lifetime;
	uint32_t usage;
	uint32_t algo;
	uint32_t lifecycle;
	uint32_t rsv;
	uint32_t crc;
};

uint32_t prepare_msg_get_key_attr(void *phdl,
				  void *cmd_buf, void *rsp_buf,
				  uint32_t *cmd_msg_sz,
				  uint32_t *rsp_msg_sz,
				  uint32_t msg_hdl,
				  void *args);

uint32_t proc_msg_rsp_get_key_attr(void *rsp_buf, void *args);
#endif
