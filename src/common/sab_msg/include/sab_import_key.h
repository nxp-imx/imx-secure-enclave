// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#ifndef SAB_MANAGE_KEY_H
#define SAB_MANAGE_KEY_H

#include <stdint.h>

#include "sab_msg_def.h"

struct sab_cmd_import_key_msg {
	struct sab_mu_hdr hdr;
	uint32_t key_management_hdl;
	uint32_t input_lsb_addr;
	uint32_t input_size;
	uint8_t flags;
	uint8_t rsv[3];
	union {
		struct {
			uint32_t key_blob_lsb;
			uint32_t key_blob_size;
			uint32_t iv_lsb;
			uint16_t iv_size;
			uint16_t key_group;
			uint32_t key_id;
		} sign_msg;
		struct {
			uint32_t rsv1[5];
		} e2go;
	};
	uint32_t crc;
};

struct sab_cmd_import_key_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
	uint32_t key_identifier;
};


uint32_t prepare_msg_importkey(void *phdl,
			       void *cmd_buf, void *rsp_buf,
			       uint32_t *cmd_msg_sz,
			       uint32_t *rsp_msg_sz,
			       uint32_t msg_hdl,
			       void *args);

uint32_t proc_msg_rsp_importkey(void *rsp_buf, void *args);
#endif
