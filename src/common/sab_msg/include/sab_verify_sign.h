// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#ifndef SAB_VERIFY_SIGN_H
#define SAB_VERIFY_SIGN_H

#include "sab_msg_def.h"

struct sab_signature_verify_open_msg {
	struct sab_mu_hdr hdr;
	uint32_t session_handle;
	uint32_t input_address_ext;
	uint32_t output_address_ext;
	uint8_t flags;
	uint8_t reserved[3];
	uint32_t crc;
};

struct sab_signature_verify_open_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
	uint32_t sig_ver_hdl;
};

struct sab_signature_verify_close_msg {
	struct sab_mu_hdr hdr;
	uint32_t sig_ver_hdl;
};

struct sab_signature_verify_close_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
};

struct sab_signature_verify_msg {
	struct sab_mu_hdr hdr;
	uint32_t sig_ver_hdl;
	uint32_t key_addr;
	uint32_t msg_addr;
	uint32_t sig_addr;
#ifdef PSA_COMPLIANT
	uint32_t message_size;
	uint16_t sig_size;
	uint16_t key_size;
	uint16_t key_security_size;
	uint16_t key_type;
	uint8_t flags;
#define SAB_CMD_VERIFY_SIGN_RESERVED	3
	uint8_t rsv1[SAB_CMD_VERIFY_SIGN_RESERVED];
	uint32_t sig_scheme;
	uint16_t salt_len;
	uint16_t rsv2;
#else
	uint16_t key_size;
	uint16_t sig_size;
	uint32_t message_size;
	uint8_t sig_scheme;
	uint8_t flags;
#define SAB_CMD_VERIFY_SIGN_RESERVED	2
	uint8_t reserved[SAB_CMD_VERIFY_SIGN_RESERVED];
#endif
	uint32_t crc;
};

struct sab_signature_verify_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
	uint32_t verification_status;
};

uint32_t prepare_msg_verify_sign_open(void *phdl,
				      void *cmd_buf, void *rsp_buf,
				      uint32_t *cmd_msg_sz,
				      uint32_t *rsp_msg_sz,
				      uint32_t msg_hdl,
				      void *args);
uint32_t proc_msg_rsp_verify_sign_open(void *rsp_buf, void *args);

uint32_t prepare_msg_verify_sign_close(void *phdl,
				       void *cmd_buf, void *rsp_buf,
				       uint32_t *cmd_msg_sz,
				       uint32_t *rsp_msg_sz,
				       uint32_t msg_hdl,
				       void *args);

uint32_t proc_msg_rsp_verify_sign_close(void *rsp_buf, void *args);

uint32_t prepare_msg_verify_sign(void *phdl,
				 void *cmd_buf, void *rsp_buf,
				 uint32_t *cmd_msg_sz,
				 uint32_t *rsp_msg_sz,
				 uint32_t msg_hdl,
				 void *args);

uint32_t proc_msg_rsp_verify_sign(void *rsp_buf, void *args);
#endif
