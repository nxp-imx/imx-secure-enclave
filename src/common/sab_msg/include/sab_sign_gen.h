// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#ifndef SAB_SIGN_GEN_H
#define SAB_SIGN_GEN_H

#include "sab_msg_def.h"

struct sab_signature_gen_open_msg {
	struct sab_mu_hdr hdr;
	uint32_t key_store_hdl;
	uint32_t input_address_ext;
	uint32_t output_address_ext;
	uint8_t flags;
	uint8_t reserved[3];
	uint32_t crc;
};

struct sab_signature_gen_open_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
	uint32_t sig_gen_hdl;
};

struct sab_signature_gen_close_msg {
	struct sab_mu_hdr hdr;
	uint32_t sig_gen_hdl;
};

struct sab_signature_gen_close_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
};

struct sab_signature_generate_msg {
	struct sab_mu_hdr hdr;
	uint32_t sig_gen_hdl;
	uint32_t key_identifier;
	uint32_t message_addr;
	uint32_t signature_addr;
	uint32_t message_size;
	uint16_t signature_size;
#ifdef PSA_COMPLIANT
	uint8_t flags;
	uint8_t rsv1;
	uint32_t scheme_id;
	uint16_t salt_len;
	uint16_t rsv2;
#else
	uint8_t scheme_id;
	uint8_t flags;
#endif
	uint32_t crc;
};

struct sab_signature_generate_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
#ifdef PSA_COMPLIANT
	uint16_t signature_size;
	uint16_t reserved;
#endif
};

uint32_t prepare_msg_sign_gen_open(void *phdl,
		void *cmd_buf, void *rsp_buf,
		uint32_t *cmd_msg_sz,
		uint32_t *rsp_msg_sz,
		uint32_t msg_hdl,
		void *args);
uint32_t proc_msg_rsp_sign_gen_open(void *rsp_buf, void *args);

uint32_t prepare_msg_sign_gen_close(void *phdl,
		void *cmd_buf, void *rsp_buf,
		uint32_t *cmd_msg_sz,
		uint32_t *rsp_msg_sz,
		uint32_t msg_hdl,
		void *args);

uint32_t proc_msg_rsp_sign_gen_close(void *rsp_buf, void *args);

uint32_t prepare_msg_sign_generate(void *phdl,
		void *cmd_buf, void *rsp_buf,
		uint32_t *cmd_msg_sz,
		uint32_t *rsp_msg_sz,
		uint32_t msg_hdl,
		void *args);

uint32_t proc_msg_rsp_sign_generate(void *rsp_buf, void *args);

#endif
