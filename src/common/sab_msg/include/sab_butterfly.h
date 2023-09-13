// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SAB_BUT_H
#define SAB_BUT_H

#include "sab_msg_def.h"

struct sab_cmd_butterfly_key_exp_msg {
	struct sab_mu_hdr hdr;
	uint32_t key_management_handle;
	uint32_t key_identifier;
	uint32_t expansion_function_value_addr;
	uint32_t hash_value_addr;
	uint32_t pr_reconstruction_value_addr;
	uint8_t expansion_function_value_size;
	uint8_t hash_value_size;
	uint8_t pr_reconstruction_value_size;
	uint8_t flags;
	uint32_t dest_key_identifier;
	uint32_t output_address;
	uint16_t output_size;
	uint8_t key_type;
	uint8_t rsv;
	uint16_t key_group;
	uint16_t key_info;
	uint32_t crc;
};

struct sab_cmd_butterfly_key_exp_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
	uint32_t dest_key_identifier;
};

uint32_t prepare_msg_butterfly(void *phdl,
			       void *cmd_buf, void *rsp_buf,
			       uint32_t *cmd_msg_sz,
			       uint32_t *rsp_msg_sz,
			       uint32_t msg_hdl,
			       void *args);

uint32_t proc_msg_rsp_butterfly(void *rsp_buf, void *args);

#endif
