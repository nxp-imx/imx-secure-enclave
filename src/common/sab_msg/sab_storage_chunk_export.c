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

#include "sab_storage_chunk_export.h"
#include "sab_messaging.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t parse_cmd_prep_rsp_storage_chunk_export(struct nvm_ctx_st *nvm_ctx_param,
						 void *cmd_buf,
						 void *rsp_buf,
						 uint32_t *cmd_len,
						 uint32_t *rsp_msg_info,
						 void **data,
						 uint32_t *data_sz,
						 uint8_t *prev_cmd_id,
						 uint8_t *next_cmd_id)
{
	uint32_t err = 0u;
	uint32_t data_len;
	struct nvm_chunk_hdr *chunk = NULL;
	uint32_t blob_size = 0u;

	struct sab_cmd_key_store_chunk_export_rsp *resp =
			 (struct sab_cmd_key_store_chunk_export_rsp *)rsp_buf;
	struct sab_cmd_key_store_chunk_export_msg *msg =
			 (struct sab_cmd_key_store_chunk_export_msg *)cmd_buf;

	*prev_cmd_id = msg->hdr.command;
	*next_cmd_id = NEXT_EXPECTED_CMD_NONE;
	resp->rsp_code = SAB_FAILURE_STATUS;

	/* Consistency check of message length. */
	err = (uint32_t)sizeof(struct sab_cmd_key_store_chunk_export_msg);
	if (*cmd_len != err)
		goto out;

	/* Do not execute operation if error is detected in previous steps */
	if (*rsp_msg_info != SAB_SUCCESS_STATUS) {
		resp->rsp_code = *rsp_msg_info;
		goto out;
	}

	/* Extract length of the blob from the message. */
	blob_size = msg->chunk_size;
	data_len = msg->chunk_size + (uint32_t)sizeof(struct nvm_header_s);

	if ((msg->chunk_size == 0u) || (data_len > 16u*1024u)) {
		/*
		 * Fixing arbitrary maximum blob size to 16k
		 * for sanity checks.
		 */
		goto out;
	}

	/* Allocate memory for receiving data. */
	chunk = (struct nvm_chunk_hdr *)plat_os_abs_malloc((uint32_t)
							   sizeof(struct nvm_chunk_hdr));

	if (chunk) {
		chunk->data = plat_os_abs_malloc(data_len);
		chunk->blob_id = ((uint64_t)(msg->blob_id_ext) << 32u)
			| (uint64_t)(msg->blob_id);
		chunk->len = data_len;
	}

	if (!chunk || !chunk->data) {
		/*
		 * If allocation failed the response should be sent to platform
		 * with an error code. Process is stopped after.
		 */
		goto out;
	}

	set_phy_addr_to_words(&resp->chunk_export_address,
			      0u,
			      plat_os_abs_data_buf(nvm_ctx_param->phdl,
						   chunk->data +
						   (uint32_t)sizeof(struct nvm_header_s),
						   blob_size,
						   0u));
	resp->rsp_code = SAB_SUCCESS_STATUS;

	*data = (struct nvm_chunk_hdr *)chunk;
	*next_cmd_id = SAB_STORAGE_EXPORT_FINISH_REQ;

out:
	*rsp_msg_info = sizeof(struct sab_cmd_key_store_chunk_export_rsp);

	return resp->rsp_code;
}
