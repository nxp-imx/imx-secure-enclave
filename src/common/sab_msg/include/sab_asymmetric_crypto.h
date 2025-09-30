// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#ifndef SAB_ASYMMETRIC_CRYPTO_H
#define SAB_ASYMMETRIC_CRYPTO_H

#include <stdint.h>

#include "sab_msg_def.h"

#ifdef PSA_COMPLIANT
struct sab_cmd_asymmetric_enc_open_msg {
	struct sab_mu_hdr hdr;
	uint32_t key_store_handle;
	uint32_t input_pointer_msb;
	uint32_t output_pointer_msb;
	uint8_t flags;
	uint8_t reserved[3];
	uint32_t crc;
};

struct sab_cmd_asymmetric_enc_open_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
	uint32_t asymmetric_enc_handle;
};

struct sab_cmd_asymmetric_enc_close_msg {
	struct sab_mu_hdr hdr;
	uint32_t asymmetric_enc_handle;
};

struct sab_cmd_asymmetric_enc_close_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
};

struct sab_cmd_asymmetric_enc_msg {
	struct sab_mu_hdr hdr;
	uint32_t asymmetric_enc_handle;
	uint32_t key_id_addr;
	uint32_t plaintext_addr;
	uint32_t ciphertext_addr;
	uint32_t label_addr;
	uint32_t plaintext_size;
	uint32_t ciphertext_size;
	uint32_t label_size;
	uint8_t flags;
	uint8_t reserved[3];
	uint32_t algorithm;
	uint32_t input_plainkey_size;
	uint16_t input_plainkey_type;
	uint16_t input_plainkey_security_size;
	uint32_t reserved1;
	uint32_t crc;
};

struct sab_cmd_asymmetric_enc_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
	uint32_t output_size;
};

uint32_t prepare_msg_asymmetric_enc_open(void *phdl,
					 void *cmd_buf,
					 void *rsp_buf,
					 uint32_t *cmd_msg_sz,
					 uint32_t *rsp_msg_sz,
					 uint32_t msg_hdl,
					 void *args);

uint32_t proc_msg_rsp_asymmetric_enc_open(void *rsp_buf, void *args);

uint32_t prepare_msg_asymmetric_enc_close(void *phdl,
					  void *cmd_buf,
					  void *rsp_buf,
					  uint32_t *cmd_msg_sz,
					  uint32_t *rsp_msg_sz,
					  uint32_t msg_hdl,
					  void *args);

uint32_t proc_msg_rsp_asymmetric_enc_close(void *rsp_buf, void *args);

uint32_t prepare_msg_asymmetric_enc(void *phdl,
				    void *cmd_buf,
				    void *rsp_buf,
				    uint32_t *cmd_msg_sz,
				    uint32_t *rsp_msg_sz,
				    uint32_t msg_hdl,
				    void *args);

uint32_t proc_msg_rsp_asymmetric_enc(void *rsp_buf, void *args);
#endif
#endif
