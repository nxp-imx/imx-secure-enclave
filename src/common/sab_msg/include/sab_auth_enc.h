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

#ifndef SAB_AUTH_ENC_H
#define SAB_AUTH_ENC_H

#include <stdint.h>

#include "sab_msg_def.h"

struct sab_cmd_auth_enc_msg {
	struct sab_mu_hdr hdr;
	uint32_t cipher_handle;
	uint32_t key_id;
	uint32_t iv_address;
	uint16_t iv_size;
#ifdef PSA_COMPLIANT
	uint8_t flags;
	uint8_t rsv1;
	uint32_t ae_algo;
#else
	uint8_t  ae_algo;
	uint8_t  flags;
#endif
	uint32_t aad_address;
	uint16_t aad_size;
	uint16_t rsv;
	uint32_t input_address;
	uint32_t output_address;
	uint32_t input_length;
	uint32_t output_length;
	uint32_t crc;
};

struct sab_cmd_auth_enc_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
#ifdef PSA_COMPLIANT
	uint32_t output_size;
#endif
};

uint32_t prepare_msg_auth_enc(void *phdl,
		void *cmd_buf, void *rsp_buf,
		uint32_t *cmd_msg_sz,
		uint32_t *rsp_msg_sz,
		uint32_t msg_hdl,
		void *args);

uint32_t proc_msg_rsp_auth_enc(void *rsp_buf, void *args);

#endif
