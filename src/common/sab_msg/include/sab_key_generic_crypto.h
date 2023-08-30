// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SAB_KEY_GENERIC_CRYPTO_H
#define SAB_KEY_GENERIC_CRYPTO_H

#include "sab_msg_def.h"

struct sab_key_generic_crypto_srv_open_msg {
	struct sab_mu_hdr header;
	uint32_t session_handle;
	uint32_t input_address_ext;
	uint32_t output_address_ext;
	uint8_t flags;
	uint8_t rsv[3];
	uint32_t crc;
};

struct sab_key_generic_crypto_srv_open_rsp {
	struct sab_mu_hdr header;
	uint32_t rsp_code;
	uint32_t key_generic_crypto_srv_handle;
};

struct sab_key_generic_crypto_srv_close_msg {
	struct sab_mu_hdr header;
	uint32_t key_generic_crypto_srv_handle;
};

struct sab_key_generic_crypto_srv_close_rsp {
	struct sab_mu_hdr header;
	uint32_t rsp_code;
};

struct sab_key_generic_crypto_srv_msg {
	struct sab_mu_hdr header;
	uint32_t key_generic_crypto_srv_handle;
	uint32_t key_address;
	uint32_t iv_address;
	uint16_t iv_size;
	uint8_t key_size;
	uint8_t crypto_algo;
	uint32_t aad_address;
	uint16_t aad_size;
	uint8_t tag_size;
	uint8_t flags;
	uint32_t input_address;
	uint32_t output_address;
	uint32_t input_length;
	uint32_t output_length;
	uint32_t rsv;
	uint32_t crc;
};

struct sab_key_generic_crypto_srv_rsp {
	struct sab_mu_hdr header;
	uint32_t rsp_code;
};

uint32_t prepare_msg_key_generic_crypto_open(void *phdl,
					     void *cmd_buf, void *rsp_buf,
					     uint32_t *cmd_msg_sz,
					     uint32_t *rsp_msg_sz,
					     uint32_t msg_hdl,
					     void *args);

uint32_t proc_msg_rsp_key_generic_crypto_open(void *rsp_buf, void *args);

uint32_t prepare_msg_key_generic_crypto_close(void *phdl,
					      void *cmd_buf, void *rsp_buf,
					      uint32_t *cmd_msg_sz,
					      uint32_t *rsp_msg_sz,
					      uint32_t msg_hdl,
					      void *args);

uint32_t proc_msg_rsp_key_generic_crypto_close(void *rsp_buf, void *args);

uint32_t prepare_msg_key_generic_crypto(void *phdl,
					void *cmd_buf, void *rsp_buf,
					uint32_t *cmd_msg_sz,
					uint32_t *rsp_msg_sz,
					uint32_t msg_hdl,
					void *args);

uint32_t proc_msg_rsp_key_generic_crypto(void *rsp_buf, void *args);
#endif
