/*
 * Copyright 2023 NXP
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

#ifndef SAB_STORAGE_GET_CHUNK_H
#define SAB_STORAGE_GET_CHUNK_H

#include "sab_nvm.h"
#include "sab_msg_def.h"

struct sab_cmd_key_store_chunk_get_msg {
	struct sab_mu_hdr hdr;
	uint32_t storage_handle;
	uint32_t blob_id;
	uint32_t blob_id_ext;
};

struct sab_cmd_key_store_chunk_get_rsp {
	struct sab_mu_hdr hdr;
	uint32_t chunk_size;
	uint32_t chunk_addr;
	uint32_t rsp_code;
};

uint32_t parse_cmd_prep_rsp_storage_get_chunk(struct nvm_ctx_st *nvm_ctx_param,
					      void *cmd_buf,
					      void *rsp_buf,
					      uint32_t *cmd_len,
					      uint32_t *rsp_len,
					      void **data,
					      uint32_t *data_sz,
					      uint8_t *next_cmd_id);
#endif
