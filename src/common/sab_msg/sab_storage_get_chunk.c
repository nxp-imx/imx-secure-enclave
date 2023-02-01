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

#include <errno.h>
#include <string.h>

#include "sab_storage_get_chunk.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t parse_cmd_prep_rsp_storage_get_chunk(struct nvm_ctx_st *nvm_ctx_param,
					      void *cmd_buf,
					      void *rsp_buf,
					      uint32_t *cmd_len,
					      uint32_t *rsp_len,
					      void **data,
					      uint32_t *data_sz,
					      uint8_t *next_cmd_id)
{
	uint64_t blob_id;
	uint64_t plat_addr;
	uint32_t err = 1u;
	struct nvm_header_s nvm_hdr;
	uint32_t ret = SAB_FAILURE_STATUS;

	struct sab_cmd_key_store_chunk_get_rsp *resp =
			 (struct sab_cmd_key_store_chunk_get_rsp *) rsp_buf;
	struct sab_cmd_key_store_chunk_get_msg *msg =
			 (struct sab_cmd_key_store_chunk_get_msg *)cmd_buf;

	/* Consistency check of message length. */
	if (*cmd_len !=
		 (int32_t)sizeof(struct sab_cmd_key_store_chunk_get_msg)) {
		goto out;
	}

	blob_id = ((uint64_t)(msg->blob_id_ext) << 32u)
		| (uint64_t)msg->blob_id;
	if (blob_id == 0u) {
		goto out;
	}

	if (plat_os_abs_storage_read_chunk(
				nvm_ctx_param->phdl,
				(uint8_t *)&nvm_hdr,
				(uint32_t)sizeof(nvm_hdr),
				blob_id,
				nvm_ctx_param->nvm_dname)
			== (int32_t)sizeof(nvm_hdr)) {
		*data = plat_os_abs_malloc(nvm_hdr.size);
		if (*data != NULL) {
			if (plat_os_abs_storage_read_chunk(
						nvm_ctx_param->phdl,
						*data,
						nvm_hdr.size,
						blob_id,
						nvm_ctx_param->nvm_dname)
					== (int32_t)nvm_hdr.size) {
				err = 0u;
			}
		} else {
			goto out;
		}
	}

	if (err == 0u) {
		resp->chunk_size = nvm_hdr.size
			- (uint32_t)sizeof(struct nvm_header_s);

		plat_addr = plat_os_abs_data_buf(nvm_ctx_param->phdl,
				*data + (uint32_t)sizeof(struct nvm_header_s),
				nvm_hdr.size - (uint32_t)sizeof(struct nvm_header_s),
				DATA_BUF_IS_INPUT);

		resp->chunk_addr =  (uint32_t)(plat_addr & 0xFFFFFFFFu);
		resp->rsp_code = SAB_SUCCESS_STATUS;
		ret = resp->rsp_code;
	} else {
		resp->chunk_size = 0u;
		resp->chunk_addr = 0u;
		resp->rsp_code = SAB_FAILURE_STATUS;
		ret = resp->rsp_code;
	}

	*next_cmd_id = SAB_STORAGE_CHUNK_GET_DONE_REQ;
	*rsp_len = sizeof(struct sab_cmd_key_store_chunk_get_rsp);
out:
	return ret;
}
