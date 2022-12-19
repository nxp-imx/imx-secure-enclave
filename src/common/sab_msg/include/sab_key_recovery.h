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

#ifndef SAB_KEY_RECOVERY_H
#define SAB_KEY_RECOVERY_H

#include <stdint.h>

#include "sab_msg_def.h"

struct sab_cmd_pub_key_recovery_msg {
	struct sab_mu_hdr hdr;
	uint32_t key_store_handle;
	uint32_t key_identifier;
	uint32_t out_key_addr_ext;
	uint32_t out_key_addr;
	uint16_t out_key_size;
#ifdef PSA_COMPLIANT
	uint16_t rsv;
#else
	uint8_t key_type;
	uint8_t flags;
#endif
	uint32_t crc;
};

struct sab_cmd_pub_key_recovery_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
#ifdef PSA_COMPLIANT
	uint16_t out_key_size;
	uint16_t reserved;
#endif
};

uint32_t prepare_msg_key_recovery(void *phdl,
		void *cmd_buf, void *rsp_buf,
		uint32_t *cmd_msg_sz,
		uint32_t *rsp_msg_sz,
		uint32_t msg_hdl,
		void *args);

uint32_t proc_msg_rsp_key_recovery(void *rsp_buf, void *args);
#endif
