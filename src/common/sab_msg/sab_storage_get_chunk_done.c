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

#include "sab_storage_get_chunk_done.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t parse_cmd_prep_rsp_storage_get_chunk_done(struct nvm_ctx_st *nvm_ctx_param,
						  void *cmd_buf,
						  void *rsp_buf,
						  uint32_t *cmd_len,
						  uint32_t *rsp_len,
						  void **data,
						  uint32_t *data_sz,
						  uint8_t *next_cmd_id)
{
	uint32_t ret = SAB_FAILURE_STATUS;
	struct sab_cmd_key_store_chunk_get_done_msg *finish_msg =
		 (struct sab_cmd_key_store_chunk_get_done_msg *)cmd_buf;
	struct sab_cmd_key_store_chunk_get_done_rsp *finish_rsp =
		 (struct sab_cmd_key_store_chunk_get_done_rsp *)rsp_buf;

	if (*cmd_len !=
		 (int32_t)sizeof(struct sab_cmd_key_store_chunk_get_done_msg)) {
		return ret;
	}

	if (finish_msg->get_status != SAB_CHUNK_GET_STATUS_SUCCEEDED) {
		/* Notification that get chunk failed. */
		finish_rsp->rsp_code = SAB_FAILURE_STATUS;
		goto out;
	}

	finish_rsp->rsp_code = SAB_SUCCESS_STATUS;
	*rsp_len = sizeof(struct sab_cmd_key_store_chunk_get_done_rsp);
	*next_cmd_id = NEXT_EXPECTED_CMD_NONE;
	ret = finish_rsp->rsp_code;

out:
	return ret;
}
