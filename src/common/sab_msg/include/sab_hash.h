/*
 * Copyright 2022 NXP
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

#ifndef SAB_HASH_H
#define SAB_HASH_H

#include "sab_msg_def.h"

struct sab_hash_open_msg {
	struct sab_mu_hdr hdr;
	uint32_t session_handle;
	uint32_t input_address_ext;
	uint32_t output_address_ext;
	uint8_t flags;
	uint8_t reserved[3];
	uint32_t crc;
};

struct sab_hash_open_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
	uint32_t hash_hdl;
};

struct sab_hash_close_msg {
	struct sab_mu_hdr hdr;
	uint32_t hash_hdl;
};

struct sab_hash_close_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
};

struct sab_hash_one_go_msg {
	struct sab_mu_hdr hdr;
	uint32_t hash_hdl;
	uint32_t input_addr;
	uint32_t output_addr;
	uint32_t input_size;
	uint32_t output_size;
#ifdef PSA_COMPLIANT
#define SAB_HASH_RESERVED_BYTES		3
	uint8_t flags;
	uint8_t reserved[SAB_HASH_RESERVED_BYTES];
	uint32_t algo;
#else
#define SAB_HASH_RESERVED_BYTES		2
	uint8_t algo;
	uint8_t flags;
	uint8_t reserved[SAB_HASH_RESERVED_BYTES];
#endif
	uint32_t crc;
};

struct sab_hash_one_go_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
#ifdef PSA_COMPLIANT
	uint32_t output_size;
#endif
};

uint32_t prepare_msg_hash_one_go(void *phdl,
				 void *cmd_buf, void *rsp_buf,
				 uint32_t *cmd_msg_sz,
				 uint32_t *rsp_msg_sz,
				 uint32_t msg_hdl,
				 void *args);

uint32_t proc_msg_rsp_hash_one_go(void *rsp_buf, void *args);

uint32_t prepare_msg_hash_open_req(void *phdl,
				   void *cmd_buf, void *rsp_buf,
				   uint32_t *cmd_msg_sz,
				   uint32_t *rsp_msg_sz,
				   uint32_t msg_hdl,
				   void *args);

uint32_t proc_msg_rsp_hash_open_req(void *rsp_buf, void *args);

uint32_t prepare_msg_hash_close_req(void *phdl,
				    void *cmd_buf, void *rsp_buf,
				    uint32_t *cmd_msg_sz,
				    uint32_t *rsp_msg_sz,
				    uint32_t msg_hdl,
				    void *args);

uint32_t proc_msg_rsp_hash_close_req(void *rsp_buf, void *args);
#endif
