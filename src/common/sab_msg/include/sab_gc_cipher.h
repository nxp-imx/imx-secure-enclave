// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#ifndef SAB_GC_CIPHER_H
#define SAB_GC_CIPHER_H

#include <stdint.h>

#include "sab_msg_def.h"

struct sab_cmd_gc_cipher_msg {
	struct sab_mu_hdr hdr;
	uint32_t in_addr;
	uint32_t out_addr;
	uint32_t data_size;
	uint32_t key_addr;
	uint32_t key_size;
	uint32_t iv_addr;
	uint32_t iv_size;
	uint8_t mode;
	uint8_t algo;
	uint16_t rsv;
	uint32_t crc;
};

struct sab_cmd_gc_cipher_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
};

uint32_t prepare_msg_gc_cipher(void *phdl,
			       void *cmd_buf, void *rsp_buf,
			       uint32_t *cmd_msg_sz,
			       uint32_t *rsp_msg_sz,
			       uint32_t msg_hdl,
			       void *args);

uint32_t proc_msg_gc_cipher(void *rsp_buf, void *args);
#endif
