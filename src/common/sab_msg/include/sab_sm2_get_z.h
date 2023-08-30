// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SAB_SM2_GET_Z_H
#define SAB_SM2_GET_Z_H

#include "sab_msg_def.h"

struct sab_cmd_sm2_get_z_msg {
	struct sab_mu_hdr hdr;
	uint32_t session_handle;
	uint32_t input_address_ext;
	uint32_t public_key_address;
	uint32_t id_address;
	uint32_t output_address_ext;
	uint32_t z_value_address;
	uint16_t public_key_size;
	uint8_t id_size;
	uint8_t z_size;
	uint8_t key_type;
	uint8_t flags;
	uint16_t reserved;
	uint32_t crc;
};

struct sab_cmd_sm2_get_z_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
};

uint32_t prepare_msg_sm2_get_z(void *phdl,
			       void *cmd_buf,
			       void *rsp_buf,
			       uint32_t *cmd_msg_sz,
			       uint32_t *rsp_msg_sz,
			       uint32_t msg_hdl,
			       void *args);

uint32_t proc_msg_rsp_sm2_get_z(void *rsp_buf, void *args);

#endif
