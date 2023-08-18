// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SAB_SM2_ECES_H
#define SAB_SM2_ECES_H

#include "sab_msg_def.h"

struct sab_cmd_sm2_eces_enc_msg {
	struct sab_mu_hdr hdr;
	uint32_t session_handle;
	uint32_t input_addr_ext;
	uint32_t input_addr;
	uint32_t key_addr_ext;
	uint32_t key_addr;
	uint32_t output_addr_ext;
	uint32_t output_addr;
	uint32_t input_size;
	uint32_t output_size;
	uint16_t key_size;
	uint8_t key_type;
	uint8_t flags;
	uint32_t crc;
};

struct sab_cmd_sm2_eces_enc_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
};

struct sab_cmd_sm2_eces_dec_open_msg {
	struct sab_mu_hdr hdr;
	uint32_t key_store_handle;
	uint32_t input_address_ext;
	uint32_t output_address_ext;
	uint8_t flags;
	uint8_t rsv[3];
	uint32_t crc;
};

struct sab_cmd_sm2_eces_dec_open_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
	uint32_t sm2_eces_handle;
};

struct sab_cmd_sm2_eces_dec_close_msg {
	struct sab_mu_hdr hdr;
	uint32_t sm2_eces_handle;
};

struct sab_cmd_sm2_eces_dec_close_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
};

struct sab_cmd_sm2_eces_dec_msg {
	struct sab_mu_hdr hdr;
	uint32_t sm2_eces_handle;
	uint32_t key_id;
	uint32_t input_address;
	uint32_t output_address;
	uint32_t input_size;
	uint32_t output_size;
	uint8_t key_type;
	uint8_t  flags;
	uint16_t rsv;
	uint32_t crc;
};

struct sab_cmd_sm2_eces_dec_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
};

uint32_t prepare_msg_sm2_eces_open_req(void *phdl,
				       void *cmd_buf, void *rsp_buf,
				       uint32_t *cmd_msg_sz,
				       uint32_t *rsp_msg_sz,
				       uint32_t msg_hdl,
				       void *args);

uint32_t proc_msg_rsp_sm2_eces_open_req(void *rsp_buf, void *args);

uint32_t prepare_msg_sm2_eces_close_req(void *phdl,
					void *cmd_buf, void *rsp_buf,
					uint32_t *cmd_msg_sz,
					uint32_t *rsp_msg_sz,
					uint32_t msg_hdl,
					void *args);

uint32_t proc_msg_rsp_sm2_eces_close_req(void *rsp_buf, void *args);

uint32_t prepare_msg_sm2_eces_encryption(void *phdl,
					 void *cmd_buf, void *rsp_buf,
					 uint32_t *cmd_msg_sz,
					 uint32_t *rsp_msg_sz,
					 uint32_t msg_hdl,
					 void *args);

uint32_t proc_msg_rsp_sm2_eces_encryption(void *rsp_buf, void *args);

uint32_t prepare_msg_sm2_eces_decryption(void *phdl,
					 void *cmd_buf, void *rsp_buf,
					 uint32_t *cmd_msg_sz,
					 uint32_t *rsp_msg_sz,
					 uint32_t msg_hdl,
					 void *args);

uint32_t proc_msg_rsp_sm2_eces_decryption(void *rsp_buf, void *args);

#endif
