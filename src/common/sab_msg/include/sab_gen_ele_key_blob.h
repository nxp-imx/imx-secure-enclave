// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#ifndef SAB_GEN_ELE_KEY_BLOB_H
#define SAB_GEN_ELE_KEY_BLOB_H

#include "sab_msg_def.h"

struct rom_cmd_gen_ele_key_blob_msg {
	struct sab_mu_hdr hdr;
	union {
		uint32_t key_id;
		struct {
			uint8_t otfad_key_struct_idx;
			uint8_t otfad_inst;
			uint16_t key_id_reserved;
		};
	};
	uint32_t reserved;
	uint32_t load_addr;
	uint32_t reserved2;
	uint32_t store_addr;
	uint16_t max_export_sz;
	uint16_t reserved3;
	uint32_t crc;
};

struct rom_cmd_gen_ele_key_blob_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
};

uint32_t proc_msg_rsp_gen_ele_key_blob(void *rsp_buf, void *args);
uint32_t prepare_msg_gen_ele_key_blob(void *phdl, void *cmd_buf, void *rsp_buf,
				      uint32_t *cmd_msg_sz, uint32_t *rsp_msg_sz,
				      uint32_t msg_hdl, void *args);
#endif
