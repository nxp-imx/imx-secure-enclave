// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SAB_DATA_STORAG_H
#define SAB_DATA_STORAGE_H

#include "sab_msg_def.h"

struct sab_cmd_data_storage_open_msg {
	struct sab_mu_hdr hdr;
	uint32_t key_store_handle;
	uint32_t input_address_ext;
	uint32_t output_address_ext;
	uint8_t flags;
	uint8_t rsv[3];
	uint32_t crc;
};

struct sab_cmd_data_storage_open_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
	uint32_t data_storage_handle;
};

struct sab_cmd_data_storage_close_msg {
	struct sab_mu_hdr hdr;
	uint32_t data_storage_handle;
};

struct sab_cmd_data_storage_close_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
};

struct sab_cmd_data_storage_msg {
	struct sab_mu_hdr hdr;
	uint32_t data_storage_handle;
#ifdef PSA_COMPLIANT
	uint8_t flags;
	uint8_t rsv[3];
	uint32_t data_id;
	uint32_t data_address;
	uint32_t data_size;
	uint32_t rsv2;
#else /* SECO */
	uint32_t data_address;
	uint32_t data_size;
	uint16_t data_id;
	uint8_t flags;
	uint8_t rsv;
#endif
	uint32_t crc;
};

struct sab_cmd_data_storage_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
#ifdef PSA_COMPLIANT
	uint32_t out_data_size;
#endif
};

uint32_t prepare_msg_data_storage(void *phdl,
				  void *cmd_buf, void *rsp_buf,
				  uint32_t *cmd_msg_sz,
				  uint32_t *rsp_msg_sz,
				  uint32_t msg_hdl,
				  void *args);

uint32_t proc_msg_rsp_data_storage(void *rsp_buf, void *args);

uint32_t prepare_msg_data_storage_open_req(void *phdl,
					   void *cmd_buf, void *rsp_buf,
					   uint32_t *cmd_msg_sz,
					   uint32_t *rsp_msg_sz,
					   uint32_t msg_hdl,
					   void *args);

uint32_t proc_msg_rsp_data_storage_open_req(void *rsp_buf, void *args);

uint32_t prepare_msg_data_storage_close_req(void *phdl,
					    void *cmd_buf, void *rsp_buf,
					    uint32_t *cmd_msg_sz,
					    uint32_t *rsp_msg_sz,
					    uint32_t msg_hdl,
					    void *args);

uint32_t proc_msg_rsp_data_storage_close_req(void *rsp_buf, void *args);
#endif
