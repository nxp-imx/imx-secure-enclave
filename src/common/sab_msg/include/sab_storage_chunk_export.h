// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SAB_STORAGE_CHUNK_EXPORT_H
#define SAB_STORAGE_CHUNK_EXPORT_H

#include "sab_nvm.h"
#include "sab_msg_def.h"

struct sab_cmd_key_store_chunk_export_msg {
	struct sab_mu_hdr hdr;
	uint32_t storage_handle;
	uint32_t chunk_size;
	struct sab_blob_id blob_id;
	uint32_t crc;
};

struct sab_cmd_key_store_chunk_export_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
	uint32_t chunk_export_address;
};

uint32_t parse_cmd_prep_rsp_storage_chunk_export(struct nvm_ctx_st *nvm_ctx_param,
						 void *cmd_buf,
						 void *rsp_buf,
						 uint32_t *cmd_len,
						 uint32_t *rsp_msg_info,
						 void **data,
						 uint32_t *data_sz,
						 uint8_t *prev_cmd_id,
						 uint8_t *next_cmd_id);
#endif

