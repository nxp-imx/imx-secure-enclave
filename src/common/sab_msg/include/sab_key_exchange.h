// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SAB_KEY_EXCHANGE_H
#define SAB_KEY_EXCHANGE_H

#include "sab_msg_def.h"

struct sab_cmd_key_exchange_msg {
	struct sab_mu_hdr hdr;
	uint32_t key_management_handle;
	uint32_t key_identifier;
	uint32_t shared_key_identifier_array;
	uint32_t ke_input_addr;
	uint32_t ke_output_addr;
	uint32_t kdf_input_data;
	uint32_t kdf_output_data;
	uint16_t shared_key_group;
	uint16_t shared_key_info;
	uint8_t shared_key_type;
	uint8_t initiator_public_data_type;
	uint8_t key_exchange_algorithm;
	uint8_t kdf_algorithm;
	uint16_t ke_input_data_size;
	uint16_t ke_output_data_size;
	uint8_t shared_key_identifier_array_size;
	uint8_t kdf_input_size;
	uint8_t kdf_output_size;
	uint8_t flags;
	uint32_t crc;
};

struct sab_cmd_key_exchange_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
};

uint32_t prepare_msg_key_exchange(void *phdl,
				  void *cmd_buf, void *rsp_buf,
				  uint32_t *cmd_msg_sz,
				  uint32_t *rsp_msg_sz,
				  uint32_t msg_hdl,
				  void *args);

uint32_t proc_msg_rsp_key_exchange(void *rsp_buf, void *args);

#endif
