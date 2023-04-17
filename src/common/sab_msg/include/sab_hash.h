// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
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
#ifdef PSA_COMPLIANT
	uint32_t addr_msb;
	uint32_t ctx_addr;
#else
	uint32_t hash_hdl;
#endif
	uint32_t input_addr;
	uint32_t output_addr;
	uint32_t input_size;
	uint32_t output_size;
#ifdef PSA_COMPLIANT
#define SAB_HASH_RESERVED_BYTES		1
	uint8_t flags;
	uint8_t reserved[SAB_HASH_RESERVED_BYTES];
	uint16_t ctx_size;
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
	uint16_t context_size;
	uint16_t rsv;
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
