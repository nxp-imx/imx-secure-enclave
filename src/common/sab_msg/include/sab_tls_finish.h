// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SAB_TLS_FINISH_H
#define SAB_TLS_FINISH_H

#include "sab_msg_def.h"

struct sab_cmd_tls_finish_msg {
	struct sab_mu_hdr hdr;
	uint32_t        key_management_handle;
	uint32_t        key_identifier;
	uint32_t        handshake_hash_input_addr;
	uint32_t        verify_data_output_addr;
	uint16_t        handshake_hash_input_size;
	uint16_t        verify_data_output_size;
	uint8_t         flags;
	uint8_t         hash_algorithm;
	uint16_t        reserved;
	uint32_t        crc;
};

struct sab_cmd_tls_finish_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
};

uint32_t prepare_msg_tls_finish(void *phdl,
				void *cmd_buf, void *rsp_buf,
				uint32_t *cmd_msg_sz,
				uint32_t *rsp_msg_sz,
				uint32_t msg_hdl,
				void *args);

uint32_t proc_msg_rsp_tls_finish(void *rsp_buf, void *args);
#endif
