// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SAB_KEY_MANAGEMENT_H
#define SAB_KEY_MANAGEMENT_H

#include "sab_msg_def.h"

struct sab_cmd_key_management_open_msg {
	struct sab_mu_hdr hdr;
	uint32_t key_store_handle;
	uint32_t input_address_ext;
	uint32_t output_address_ext;
	uint8_t flags;
	uint8_t rsv[3];
	uint32_t crc;
};

struct sab_cmd_key_management_open_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
	uint32_t key_management_handle;
};

struct sab_cmd_key_management_close_msg {
	struct sab_mu_hdr hdr;
	uint32_t key_management_handle;
};

struct sab_cmd_key_management_close_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
};

uint32_t prepare_msg_key_management_open_req(void *phdl,
					     void *cmd_buf, void *rsp_buf,
					     uint32_t *cmd_msg_sz,
					     uint32_t *rsp_msg_sz,
					     uint32_t msg_hdl,
					     void *args);

uint32_t proc_msg_rsp_key_management_open_req(void *rsp_buf, void *args);

uint32_t prepare_msg_key_management_close_req(void *phdl,
					      void *cmd_buf, void *rsp_buf,
					      uint32_t *cmd_msg_sz,
					      uint32_t *rsp_msg_sz,
					      uint32_t msg_hdl,
					      void *args);

uint32_t proc_msg_rsp_key_management_close_req(void *rsp_buf, void *args);
#endif
