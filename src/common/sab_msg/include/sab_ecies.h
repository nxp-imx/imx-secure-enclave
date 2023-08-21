// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SAB_ECIES_H
#define SAB_ECIES_H

#include "sab_msg_def.h"

struct sab_cmd_ecies_encrypt_msg {
	struct sab_mu_hdr hdr;
	uint32_t sesssion_handle;
	uint32_t input_addr_ext;
	uint32_t input_addr;
	uint32_t key_addr_ext;
	uint32_t key_addr;
	uint32_t p1_addr_ext;
	uint32_t p1_addr;
	uint32_t p2_addr_ext;
	uint32_t p2_addr;
	uint32_t output_addr_ext;
	uint32_t output_addr;
	uint32_t input_size;
	uint16_t p1_size;
	uint16_t p2_size;
	uint16_t key_size;
	uint16_t mac_size;
	uint32_t output_size;
	uint8_t key_type;
	uint8_t flags;
	uint16_t reserved;
	uint32_t crc;
};

struct sab_cmd_ecies_encrypt_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
};

struct sab_cmd_ecies_decrypt_msg {
	struct sab_mu_hdr hdr;
	uint32_t cipher_handle;
	uint32_t key_id;
	uint32_t input_address;
	uint32_t p1_addr;
	uint32_t p2_addr;
	uint32_t output_address;
	uint32_t input_size;
	uint32_t output_size;
	uint16_t p1_size;
	uint16_t p2_size;
	uint16_t mac_size;
	uint8_t key_type;
	uint8_t flags;
	uint32_t crc;
};

struct sab_cmd_ecies_decrypt_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
};

uint32_t prepare_msg_ecies_encryption(void *phdl,
				      void *cmd_buf, void *rsp_buf,
				      uint32_t *cmd_msg_sz,
				      uint32_t *rsp_msg_sz,
				      uint32_t msg_hdl,
				      void *args);

uint32_t proc_msg_rsp_ecies_encryption(void *rsp_buf, void *args);

uint32_t prepare_msg_ecies_decryption(void *phdl,
				      void *cmd_buf, void *rsp_buf,
				      uint32_t *cmd_msg_sz,
				      uint32_t *rsp_msg_sz,
				      uint32_t msg_hdl,
				      void *args);

uint32_t proc_msg_rsp_ecies_decryption(void *rsp_buf, void *args);

#endif
