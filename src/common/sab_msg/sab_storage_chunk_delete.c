// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024-2025 NXP
 */

#include <errno.h>
#include <string.h>

#include "sab_storage_chunk_delete.h"
#include "sab_messaging.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t parse_cmd_prep_rsp_chunk_delete(struct nvm_ctx_st *nvm_ctx_param,
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
	char *path = NULL;
	uint32_t err;

	struct sab_cmd_chunk_delete_rsp *resp =
			 (struct sab_cmd_chunk_delete_rsp *)rsp_buf;
	struct sab_cmd_chunk_delete_msg *msg =
			 (struct sab_cmd_chunk_delete_msg *)cmd_buf;

	*prev_cmd_id = msg->hdr.command;
	*next_cmd_id = NEXT_EXPECTED_CMD_NONE;
	resp->rsp_code = SAB_FAILURE_STATUS;

	/* Consistency check of message length. */
	if (*cmd_len != (uint32_t)sizeof(struct sab_cmd_chunk_delete_msg))
		goto out;

	if (*rsp_msg_info != plat_sab_success_tag(nvm_ctx_param->phdl)) {
		resp->rsp_code = *rsp_msg_info;
		goto out;
	}

	blob_id = &msg->blob_id;

	if (!blob_id->metadata && !blob_id->id && !blob_id->ext)
		goto out;

	if (get_chunk_file_path(&path, nvm_ctx_param->nvm_dname, blob_id)) {
		err = plat_os_abs_storage_remove_file(path, nvm_ctx_param->nvm_dname);
		if (err != PLAT_SUCCESS) {
			if (err == PLAT_ERR_NO_SUCH_FILE_DIR)
				resp->rsp_code = SAB_UNKNOWN_ID_STATUS;

			goto out;
		}

		resp->rsp_code = plat_sab_success_tag(nvm_ctx_param->phdl);
	}

out:
	if (path)
		plat_os_abs_free(path);

	*rsp_msg_info = sizeof(struct sab_cmd_chunk_delete_rsp);

	return resp->rsp_code;
}
