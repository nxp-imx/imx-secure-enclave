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

#include "sab_storage_master_export.h"

#include "plat_os_abs.h"

uint32_t parse_cmd_prep_rsp_storage_master_export(struct nvm_ctx_st *nvm_ctx_param,
						  void *cmd_buf,
						  void *rsp_buf,
						  uint32_t *cmd_len,
						  uint32_t *rsp_msg_info,
						  void **data,
						  uint32_t *data_sz,
						  uint8_t *prev_cmd_id,
						  uint8_t *next_cmd_id)
{
	uint32_t err;
	uint32_t data_len;
	uint64_t plat_addr;
	struct sab_cmd_key_store_export_start_rsp *resp
		= (struct sab_cmd_key_store_export_start_rsp *)rsp_buf;
	struct sab_cmd_key_store_export_start_msg *msg
		= (struct sab_cmd_key_store_export_start_msg *)cmd_buf;

	*prev_cmd_id = msg->hdr.command;
	*next_cmd_id = NEXT_EXPECTED_CMD_NONE;
	resp->rsp_code = SAB_FAILURE_STATUS;

	/* Consistency check of message length. */
	err = (uint32_t)sizeof(struct sab_cmd_key_store_export_start_msg);
	if (*cmd_len != err) {
		goto out;
	}

	/* Do not execute operation if error is detected in previous steps */
	if (*rsp_msg_info != SAB_SUCCESS_STATUS) {
		resp->rsp_code = *rsp_msg_info;
		goto out;
	}

	/* Extract length of the blob from the message. */
	data_len = msg->key_store_size
		+ (uint32_t)sizeof(struct nvm_header_s);

	if ((msg->key_store_size == 0u) || (data_len > 16u*1024u)) {
		/* Fixing arbitrary maximum blob size to 16k
		 * for sanity checks.
		 */
		resp->rsp_code = SAB_FAILURE_STATUS;
		goto out;
	}

	/* Allocate memory for receiving data. */
	*data = plat_os_abs_malloc(data_len);

	/* If data is NULL the response should be sent to platform
	 * with an error code. Process is stopped after.
	 */
	if (*data != NULL) {
		plat_addr = plat_os_abs_data_buf(nvm_ctx_param->phdl,
				*data + (uint32_t)sizeof(struct nvm_header_s),
				msg->key_store_size,
				0u);
		resp->key_store_export_address =
			(uint32_t)(plat_addr & 0xFFFFFFFFu);
		resp->rsp_code = SAB_SUCCESS_STATUS;
	} else {
		resp->key_store_export_address = 0;
		resp->rsp_code = SAB_FAILURE_STATUS;
	}

	resp->storage_handle = nvm_ctx_param->storage_handle;
	*data_sz = msg->key_store_size;
	*next_cmd_id = SAB_STORAGE_EXPORT_FINISH_REQ;

out:
	*rsp_msg_info = sizeof(struct sab_cmd_key_store_export_start_rsp);

	return resp->rsp_code;
}
