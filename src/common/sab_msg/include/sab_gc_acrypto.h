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

#ifndef SAB_GC_ACRYPTO_H
#define SAB_GC_ACRYPTO_H

#include <stdint.h>

#include "sab_msg_def.h"

struct sab_cmd_gc_acrypto_msg {
	struct sab_mu_hdr hdr;
	uint32_t buffers_addr_msb;
	uint32_t algorithm;
	uint8_t op_mode;
	uint8_t flags;
	uint16_t key_size;
	uint32_t data_buff1_addr;
	uint32_t data_buff2_addr;
	uint32_t data_buff1_size;
	uint32_t data_buff2_size;
	uint32_t key_buff1_addr;
	uint32_t key_buff2_addr;
	uint16_t key_buff1_size;
	uint16_t key_buff2_size;
	uint32_t rsv[2];
	uint32_t rsa_label_addr;
	uint16_t rsa_label_size;
	uint16_t rsa_salt_len;
	uint32_t crc;
};

struct sab_cmd_gc_acrypto_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
	uint32_t plaintext_len;
	uint32_t verification_status;
	uint32_t rsv;
	uint32_t crc;
};

uint32_t prepare_msg_gc_acrypto(void *phdl,
				void *cmd_buf, void *rsp_buf,
				uint32_t *cmd_msg_sz,
				uint32_t *rsp_msg_sz,
				uint32_t msg_hdl,
				void *args);

uint32_t proc_msg_gc_acrypto(void *rsp_buf, void *args);
#endif
