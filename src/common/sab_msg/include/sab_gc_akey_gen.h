// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SAB_GC_AKEY_GEN_H
#define SAB_GC_AKEY_GEN_H

#include <stdint.h>

#include "sab_msg_def.h"

struct sab_cmd_gc_akey_gen_msg {
	struct sab_mu_hdr hdr;
	uint32_t buffers_addr_msb;
	uint32_t modulus_addr;
	uint32_t priv_buff_addr;
	uint32_t pub_buff_addr;
	uint16_t modulus_size;
	uint16_t priv_buff_size;
	uint16_t pub_buff_size;
	uint16_t rsv1;
	uint16_t key_type;
	uint16_t key_size_bits;
	uint32_t rsv[2];
	uint32_t crc;
};

struct sab_cmd_gc_akey_gen_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
};

uint32_t prepare_msg_gc_akey_gen(void *phdl,
				 void *cmd_buf, void *rsp_buf,
				 uint32_t *cmd_msg_sz,
				 uint32_t *rsp_msg_sz,
				 uint32_t msg_hdl,
				 void *args);

uint32_t proc_msg_gc_akey_gen(void *rsp_buf, void *args);
#endif
