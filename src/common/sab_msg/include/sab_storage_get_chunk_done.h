// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SAB_STORAGE_GET_CHUNK_DONE_H
#define SAB_STORAGE_GET_CHUNK_DONE_H

#include "sab_nvm.h"
#include "sab_msg_def.h"

#define SAB_CHUNK_GET_STATUS_SUCCEEDED (0xCA3BB3ACu)

struct sab_cmd_key_store_chunk_get_done_msg {
	struct sab_mu_hdr hdr;
	uint32_t storage_handle;
	uint32_t get_status;
};

struct sab_cmd_key_store_chunk_get_done_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
};

uint32_t parse_cmd_prep_rsp_storage_get_chunk_done(struct nvm_ctx_st *nvm_ctx_param,
						  void *cmd_buf,
						  void *rsp_buf,
						  uint32_t *cmd_len,
						  uint32_t *rsp_msg_info,
						  void **data,
						  uint32_t *data_sz,
						  uint8_t *prev_cmd_id,
						  uint8_t *next_cmd_id);
#endif
