// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SAB_PUB_KEY_DECOMPRESSION_H
#define SAB_PUB_KEY_DECOMPRESSION_H

#include "sab_msg_def.h"

struct sab_public_key_decompression_msg {
	struct sab_mu_hdr hdr;
	uint32_t sesssion_handle;
	uint32_t input_address_ext;
	uint32_t input_address;
	uint32_t output_address_ext;
	uint32_t output_address;
	uint16_t input_size;
	uint16_t out_size;
	uint8_t key_type;
	uint8_t flags;
	uint16_t rsv;
	uint32_t crc;
};

struct sab_public_key_decompression_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
};

uint32_t prepare_msg_pub_key_decompression(void *phdl,
					   void *cmd_buf, void *rsp_buf,
					   uint32_t *cmd_msg_sz,
					   uint32_t *rsp_msg_sz,
					   uint32_t msg_hdl,
					   void *args);

uint32_t proc_msg_rsp_pub_key_decompression(void *rsp_buf, void *args);
#endif
