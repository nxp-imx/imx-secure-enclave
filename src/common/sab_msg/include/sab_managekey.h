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

struct sab_cmd_manage_key_msg {
	struct sab_mu_hdr hdr;
	uint32_t key_management_handle;
	uint32_t dest_key_identifier;
	uint32_t kek_id;
	uint16_t input_data_size;
	uint8_t flags;
	uint8_t key_type;
	uint16_t key_group;
	uint16_t key_info;
	uint32_t input_data_addr;
	uint32_t crc;
};

struct sab_cmd_manage_key_ext_msg {
	struct sab_mu_hdr hdr;
	uint32_t key_management_handle;
	uint32_t dest_key_identifier;
	uint32_t kek_id;
	uint16_t input_data_size;
	uint8_t flags;
	uint8_t key_type;
	uint16_t key_group;
	uint16_t key_info;
	uint32_t input_data_addr;
	uint8_t min_mac_len;
	uint8_t reserved[3];
	uint32_t crc;
};

struct sab_cmd_manage_key_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
	uint32_t key_identifier;
};

uint32_t prepare_msg_managekey(void *phdl,
			       void *cmd_buf, void *rsp_buf,
			       uint32_t *cmd_msg_sz,
			       uint32_t *rsp_msg_sz,
			       uint32_t msg_hdl,
			       void *args);

uint32_t prepare_msg_managekey_ext(void *phdl,
			       void *cmd_buf, void *rsp_buf,
			       uint32_t *cmd_msg_sz,
			       uint32_t *rsp_msg_sz,
			       uint32_t msg_hdl,
			       void *args);

uint32_t proc_msg_rsp_managekey(void *rsp_buf, void *args);
#endif
