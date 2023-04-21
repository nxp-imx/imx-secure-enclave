// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SAB_KEY_STORE_H
#define SAB_KEY_STORE_H

#include "sab_msg_def.h"

struct sab_cmd_key_store_open_msg {
	struct sab_mu_hdr hdr;
	uint32_t session_handle;
	uint32_t key_store_id;
	uint32_t password;
	uint16_t max_updates;
	uint8_t flags;
#ifndef PSA_COMPLIANT
	uint8_t min_mac_length;
#else
	uint8_t rsv;
#endif
	uint32_t crc;
};

struct sab_cmd_key_store_open_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
	uint32_t key_store_handle;
};

struct sab_cmd_key_store_close_msg {
	struct sab_mu_hdr hdr;
	uint32_t key_store_handle;
};

struct sab_cmd_key_store_close_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
};

uint32_t prepare_msg_key_store_open_req(void *phdl,
					void *cmd_buf, void *rsp_buf,
					uint32_t *cmd_msg_sz,
					uint32_t *rsp_msg_sz,
					uint32_t msg_hdl,
					void *args);

uint32_t proc_msg_rsp_key_store_open_req(void *rsp_buf, void *args);

uint32_t prepare_msg_key_store_close_req(void *phdl,
					 void *cmd_buf, void *rsp_buf,
					 uint32_t *cmd_msg_sz,
					 uint32_t *rsp_msg_sz,
					 uint32_t msg_hdl,
					 void *args);

uint32_t proc_msg_rsp_key_store_close_req(void *rsp_buf, void *args);
#endif
