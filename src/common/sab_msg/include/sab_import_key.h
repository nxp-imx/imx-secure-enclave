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

#ifndef SAB_MANAGE_KEY_H
#define SAB_MANAGE_KEY_H

#include <stdint.h>

#include "sab_msg_def.h"
#include "sab_msg_def.h"

struct sab_cmd_import_key_msg {
	struct sab_mu_hdr hdr;//(see Table 10)
	uint32_t key_management_hdl;
	uint32_t key_id;
	uint16_t in_priv_key_sz;
	uint16_t key_group;
	uint8_t flags;
	uint8_t key_lifetime;
	uint16_t key_usage;
	uint16_t key_type;
	uint16_t bit_key_sz;
	uint32_t permitted_algo;
	uint32_t priv_key_in_lsb_addr;
	uint32_t crc;
};

struct sab_cmd_import_key_rsp {
	struct sab_mu_hdr hdr;//(see Table 10)
	uint32_t rsp_code;
	uint32_t key_identifier;
};


uint32_t prepare_msg_importkey(void *phdl,
			       void *cmd_buf, void *rsp_buf,
			       uint32_t *cmd_msg_sz,
			       uint32_t *rsp_msg_sz,
			       uint32_t msg_hdl,
			       void *args);

uint32_t proc_msg_rsp_importkey(void *rsp_buf, void *args);
#endif
