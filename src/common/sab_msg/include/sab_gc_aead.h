// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#ifndef SAB_GC_AEAD_H
#define SAB_GC_AEAD_H

#include <stdint.h>

#include "sab_msg_def.h"

struct sab_cmd_gc_aead_msg {
	struct sab_mu_hdr hdr;
	uint32_t in_addr;
	uint32_t out_addr;
	uint32_t data_size;
	uint32_t key_addr;
	uint32_t key_size;
	uint32_t nonce_addr;
	uint32_t nonce_size;
	uint32_t aad_addr;
	uint32_t aad_size;
	uint32_t tag_addr;
	uint32_t tag_size;
	uint8_t algo;
	uint8_t mode;
	uint16_t rsv;
	uint32_t crc;
};

struct sab_cmd_gc_aead_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
};

uint32_t prepare_msg_gc_aead(void *phdl,
			     void *cmd_buf, void *rsp_buf,
			     uint32_t *cmd_msg_sz,
			     uint32_t *rsp_msg_sz,
			     uint32_t msg_hdl,
			     void *args);

uint32_t proc_msg_gc_aead(void *rsp_buf, void *args);
#endif
