// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <errno.h>
#include <stdint.h>

#include "sab_storage_master_export.h"
#include "sab_messaging.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

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
	if (*rsp_msg_info != plat_sab_success_tag(nvm_ctx_param->phdl)) {
		resp->rsp_code = *rsp_msg_info;
		goto out;
	}

	/* Extract length of the blob from the message. */
	data_len = TO_UINT16_T(msg->key_store_size) + NVM_HEADER_SZ;

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
		set_phy_addr_to_words(&resp->key_store_export_address,
				      0u,
				      plat_os_abs_data_buf(nvm_ctx_param->phdl,
							   *data + NVM_HEADER_SZ,
							   msg->key_store_size,
							   0u));
		resp->rsp_code = plat_sab_success_tag(nvm_ctx_param->phdl);
	} else {
		resp->key_store_export_address = 0;
		resp->rsp_code = plat_sab_success_tag(nvm_ctx_param->phdl);
	}

	resp->storage_handle = nvm_ctx_param->storage_handle;
	*data_sz = msg->key_store_size;
	*next_cmd_id = SAB_STORAGE_EXPORT_FINISH_REQ;

out:
	*rsp_msg_info = sizeof(struct sab_cmd_key_store_export_start_rsp);

	return resp->rsp_code;
}
