/*
 * Copyright 2023 NXP
 *
 * NXP Confidential.
 * This software is owned or controlled by NXP and may only be used strictly
 * in accordance with the applicable license terms.  By expressly accepting
 * such terms or by downloading, installing, activating and/or otherwise using
 * the software, you are agreeing that you have read, and that you agree to
 * comply with and are bound by, such license terms.  If you do not agree to be
 * bound by the applicable license terms, then you may not retain, install,
 * activate or otherwise use the software.
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
