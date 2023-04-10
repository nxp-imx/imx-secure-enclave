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
#include <stdint.h>

#include "sab_storage_export_finish.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

#if MT_SAB_STORAGE_KEY_DB_REQ
#include "sab_storage_key_db.h"
#endif

uint32_t parse_cmd_prep_rsp_storage_finish_export(struct nvm_ctx_st *nvm_ctx_param,
						  void *cmd_buf,
						  void *rsp_buf,
						  uint32_t *cmd_len,
						  uint32_t *rsp_msg_info,
						  void **data,
						  uint32_t *data_sz,
						  uint8_t *prev_cmd_id,
						  uint8_t *next_cmd_id)
{
	uint32_t err = 1u;
	uint32_t len;
	struct nvm_header_s *blob_hdr;
	uint32_t data_len;
	struct nvm_chunk_hdr *chunk = NULL;

	struct sab_cmd_key_store_export_finish_msg *msg
			= (struct sab_cmd_key_store_export_finish_msg *)cmd_buf;
	struct sab_cmd_key_store_export_finish_rsp *resp
			= (struct sab_cmd_key_store_export_finish_rsp *)rsp_buf;

	*next_cmd_id = NEXT_EXPECTED_CMD_NONE;
	resp->rsp_code = SAB_FAILURE_STATUS;

	/* Consistency check of message length. */
	if (*cmd_len
		!= (int32_t)sizeof(struct sab_cmd_key_store_export_finish_msg)) {
		goto out;
	}

	/* Do not execute operation if error is detected in previous steps */
	if (*rsp_msg_info != SAB_SUCCESS_STATUS) {
		resp->rsp_code = *rsp_msg_info;
		goto out;
	}

	if (msg->export_status != SAB_EXPORT_STATUS_SUCCESS) {
		/* Notification that export failed.
		 * Acknowledge it but stop write to NVM.
		 */
		resp->rsp_code = SAB_SUCCESS_STATUS;
		goto out;
	}
	err = 0;

	if (*prev_cmd_id == SAB_STORAGE_MASTER_EXPORT_REQ) {
		data_len = *data_sz + NVM_HEADER_SZ;

		/* fill header for sanity check when it will be re-loaded. */
		blob_hdr = (struct nvm_header_s *)*data;
		/* Used only for chunks. */
		blob_hdr->blob_id = 0u;
		blob_hdr->size = *data_sz;
		blob_hdr->crc = plat_fetch_msg_crc((uint32_t *)(*data + NVM_HEADER_SZ), *data_sz);

		/* Data have been provided by platform.
		 * Write them in NVM and acknowledge.
		 */
		if (plat_os_abs_storage_write(nvm_ctx_param->phdl,
					      *data,
					      data_len,
					      nvm_ctx_param->nvm_fname)
					      == data_len) {
			/* Success. */
			resp->rsp_code = SAB_SUCCESS_STATUS;
		} else {
			/* Notify platform of an error during write to NVM. */
			resp->rsp_code = SAB_FAILURE_STATUS;
			goto out;
		}
	} else {
		chunk = *data;
		blob_hdr = (struct nvm_header_s *)chunk->data;
		blob_hdr->size = chunk->len;
		blob_hdr->crc = plat_fetch_msg_crc((uint32_t *)(chunk->data + NVM_HEADER_SZ),
						   chunk->len);
		blob_hdr->blob_id = chunk->blob_id;

		if (plat_os_abs_storage_write_chunk(nvm_ctx_param->phdl,
						    chunk->data,
						    chunk->len,
						    chunk->blob_id,
						    nvm_ctx_param->nvm_dname)
						    != chunk->len) {
			err = 1;
			/* Notify platform of an error during write to NVM. */
			resp->rsp_code = SAB_FAILURE_STATUS;
			goto out;
		} else {
			/* Success. */
			resp->rsp_code = SAB_SUCCESS_STATUS;
		}
	}

#if MT_SAB_STORAGE_KEY_DB_REQ
	/* Update key database if needed */
	err = storage_key_db_save_persistent(blob_hdr->blob_id, nvm_ctx_param);
	if (err != 0u)
		resp->rsp_code = SAB_FAILURE_STATUS;
#endif

out:
	resp->storage_handle = nvm_ctx_param->storage_handle;
	*rsp_msg_info = sizeof(struct sab_cmd_key_store_export_finish_rsp);

	return resp->rsp_code;
}
