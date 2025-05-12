// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2025 NXP
 */

#ifndef SAB_CIPHER_H
#define SAB_CIPHER_H

#include "sab_msg_def.h"

struct sab_cmd_cipher_msg {
	struct sab_mu_hdr hdr;
	uint32_t cipher_handle;
	uint32_t key;
	uint32_t iv_address;
	uint16_t iv_size;
#ifdef PSA_COMPLIANT
	uint16_t  flags;
	uint32_t  algo;
#else
	uint8_t  algo;
	uint8_t  flags;
#endif
	uint32_t input_address;
	uint32_t output_address;
	uint32_t input_size;
	uint32_t output_size;
#ifdef PSA_COMPLIANT
	uint16_t key_size;
	uint16_t key_type;
	uint32_t context_address;
	uint16_t context_size;
	uint16_t rsv1;
	uint32_t rsv2;
#endif
	uint32_t crc;
};

struct sab_cmd_cipher_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
#ifdef PSA_COMPLIANT
	uint32_t output_size;
#endif
};

struct sab_cmd_cipher_open_msg {
	struct sab_mu_hdr hdr;
	uint32_t key_store_handle;
	uint32_t input_address_ext;
	uint32_t output_address_ext;
	uint8_t flags;
	uint8_t rsv;
	uint16_t rsv_1;
	uint32_t crc;
};

struct sab_cmd_cipher_open_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
	uint32_t cipher_handle;
};

struct sab_cmd_cipher_close_msg {
	struct sab_mu_hdr hdr;
	uint32_t cipher_handle;
};

struct sab_cmd_cipher_close_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
};

uint32_t prepare_msg_cipher(void *phdl,
			    void *cmd_buf, void *rsp_buf,
			    uint32_t *cmd_msg_sz,
			    uint32_t *rsp_msg_sz,
			    uint32_t msg_hdl,
			    void *args);

uint32_t proc_msg_rsp_cipher(void *rsp_buf, void *args);

uint32_t prepare_msg_cipher_open_req(void *phdl,
				   void *cmd_buf, void *rsp_buf,
				   uint32_t *cmd_msg_sz,
				   uint32_t *rsp_msg_sz,
				   uint32_t msg_hdl,
				   void *args);

uint32_t proc_msg_rsp_cipher_open_req(void *rsp_buf, void *args);

uint32_t prepare_msg_cipher_close_req(void *phdl,
				    void *cmd_buf, void *rsp_buf,
				    uint32_t *cmd_msg_sz,
				    uint32_t *rsp_msg_sz,
				    uint32_t msg_hdl,
				    void *args);

uint32_t proc_msg_rsp_cipher_close_req(void *rsp_buf, void *args);
#endif
