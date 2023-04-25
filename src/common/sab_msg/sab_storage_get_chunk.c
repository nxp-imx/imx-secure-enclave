// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <errno.h>
#include <string.h>

#include "sab_storage_get_chunk.h"
#include "sab_messaging.h"

#include "plat_os_abs.h"

uint32_t parse_cmd_prep_rsp_storage_get_chunk(struct nvm_ctx_st *nvm_ctx_param,
					      void *cmd_buf,
					      void *rsp_buf,
					      uint32_t *cmd_len,
					      uint32_t *rsp_msg_info,
					      void **data,
					      uint32_t *data_sz,
					      uint8_t *prev_cmd_id,
					      uint8_t *next_cmd_id)
{
	struct sab_blob_id *blob_id;

	uint32_t err = 1u;
	struct nvm_header_s nvm_hdr;

	struct sab_cmd_key_store_chunk_get_rsp *resp =
			 (struct sab_cmd_key_store_chunk_get_rsp *) rsp_buf;
	struct sab_cmd_key_store_chunk_get_msg *msg =
			 (struct sab_cmd_key_store_chunk_get_msg *)cmd_buf;

	*prev_cmd_id = msg->hdr.command;
	*next_cmd_id = NEXT_EXPECTED_CMD_NONE;
	resp->rsp_code = SAB_FAILURE_STATUS;

	/* Consistency check of message length. */
	if (*cmd_len !=
		 (int32_t)sizeof(struct sab_cmd_key_store_chunk_get_msg)) {
		goto out;
	}

	/* Do not execute operation if error is detected in previous steps */
	if (*rsp_msg_info != SAB_SUCCESS_STATUS) {
		resp->rsp_code = *rsp_msg_info;
		goto out;
	}

	blob_id = &msg->blob_id;

#ifdef CONFIG_PLAT_SECO
	if (!blob_id->id && !blob_id->ext) {
#else
	if (!blob_id->metadata && !blob_id->id && !blob_id->ext) {
#endif
		resp->rsp_code = SAB_FAILURE_STATUS;
		goto out;
	}

	if (plat_os_abs_storage_read_chunk(nvm_ctx_param->phdl,
					   (uint8_t *)&nvm_hdr,
					   NVM_HEADER_SZ,
					   blob_id,
					   nvm_ctx_param->nvm_dname)
					   == NVM_HEADER_SZ) {
		*data = plat_os_abs_malloc(nvm_hdr.size);
		if (*data != NULL) {
			if (plat_os_abs_storage_read_chunk(nvm_ctx_param->phdl,
							   *data,
							   nvm_hdr.size,
							   blob_id,
							   nvm_ctx_param->nvm_dname)
							   == nvm_hdr.size) {
				err = 0u;
			}
		} else {
			resp->rsp_code = SAB_FAILURE_STATUS;
			goto out;
		}
	}

	if (err == 0u) {
		resp->chunk_size = nvm_hdr.size - NVM_HEADER_SZ;
		set_phy_addr_to_words(&resp->chunk_addr,
				      0u,
				      plat_os_abs_data_buf(nvm_ctx_param->phdl,
							   *data + NVM_HEADER_SZ,
							   nvm_hdr.size - NVM_HEADER_SZ,
							   DATA_BUF_IS_INPUT));

		resp->rsp_code = SAB_SUCCESS_STATUS;
	} else {
		resp->chunk_size = 0u;
		resp->chunk_addr = 0u;
		resp->rsp_code = SAB_FAILURE_STATUS;
	}

	*next_cmd_id = SAB_STORAGE_CHUNK_GET_DONE_REQ;

out:
	*rsp_msg_info = sizeof(struct sab_cmd_key_store_chunk_get_rsp);

	return resp->rsp_code;
}
