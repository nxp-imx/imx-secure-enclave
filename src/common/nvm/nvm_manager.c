/*
 * Copyright 2019-2023 NXP
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

#include "sab_common_err.h"
#include "sab_msg_def.h"
#include "sab_messaging.h"
#include "nvm.h"
#include "sab_nvm.h"
#include "sab_process_msg.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

/* Storage import processing. Return 0 on success.  */
static uint32_t nvm_storage_import(struct nvm_ctx_st *nvm_ctx_param,
				   uint8_t *data, uint32_t len)
{
	struct nvm_header_s *blob_hdr;
	uint32_t ret = SAB_FAILURE_STATUS;
	int32_t error;
	uint32_t rsp_code;

	do {
		if (nvm_ctx_param->storage_handle == 0u) {
			break;
		}

		blob_hdr = (struct nvm_header_s *)data;

		/* Sanity check on the provided data. */
		if (blob_hdr->size
			+ (uint32_t)sizeof(struct nvm_header_s) != len) {
			break;
		}

		if (plat_fetch_msg_crc((uint32_t *)(data + sizeof(struct nvm_header_s)),
					blob_hdr->size) != blob_hdr->crc) {
			break;
		}

		error = process_sab_msg(nvm_ctx_param->phdl,
					nvm_ctx_param->mu_type,
					SAB_STORAGE_MASTER_IMPORT_REQ,
					MT_SAB_STORAGE_MASTER_IMPORT,
					(uint32_t)nvm_ctx_param->storage_handle,
					data, &rsp_code);
		ret = rsp_code;
	} while (false);
	return ret;
}

void nvm_close_session(void *ctx)
{
	struct nvm_ctx_st *nvm_ctx = (struct nvm_ctx_st *)ctx;
	uint32_t ret = SAB_FAILURE_STATUS;

	if (ctx == NULL) {
		printf("Error: No active context to close.\n");
		return;
	}

	if (nvm_ctx->phdl != NULL) {
		if (nvm_ctx->storage_handle != 0u) {
			ret = sab_close_storage_command(nvm_ctx->phdl,
					nvm_ctx->storage_handle,
					nvm_ctx->mu_type);
			nvm_ctx->storage_handle = 0u;
		}
		if (nvm_ctx->session_handle != 0u) {
			(void)sab_close_session_command(nvm_ctx->phdl,
					nvm_ctx->session_handle,
					nvm_ctx->mu_type);
			nvm_ctx->session_handle = 0u;
		}

		plat_os_abs_close_session(nvm_ctx->phdl);
		nvm_ctx->phdl = NULL;
	}

	plat_os_abs_free(nvm_ctx);
}

static void nvm_open_session(uint8_t flags, struct nvm_ctx_st *nvm_ctx)
{
	uint32_t err = SAB_FAILURE_STATUS;
	struct plat_mu_params mu_params;

	do {
		/* Check if structure is already in use */
		if (nvm_ctx->phdl != NULL)
			break;

		/* Open the Storage session on the MU */
		if ((flags & NVM_FLAGS_V2X) != 0u) {
			if ((flags & NVM_FLAGS_SHE) != 0u) {
				nvm_ctx->mu_type = MU_CHANNEL_V2X_SHE_NVM;
			} else {
				nvm_ctx->mu_type = MU_CHANNEL_V2X_HSM_NVM;
			}
		} else {
			if ((flags & NVM_FLAGS_SHE) != 0u) {
				nvm_ctx->mu_type = MU_CHANNEL_PLAT_SHE_NVM;
			} else {
				nvm_ctx->mu_type = MU_CHANNEL_PLAT_HSM_NVM;
			}
		}

		nvm_ctx->phdl = plat_os_abs_open_mu_channel(nvm_ctx->mu_type,
							    &mu_params);

		if (nvm_ctx->phdl == NULL) {
			break;
		}

		/* Open the SAB session on the selected security enclave */
		err = sab_open_session_command(nvm_ctx->phdl,
				&nvm_ctx->session_handle,
				nvm_ctx->mu_type,
				mu_params.mu_id,
				mu_params.interrupt_idx,
				mu_params.tz,
				mu_params.did,
				SAB_OPEN_SESSION_PRIORITY_LOW,
				((flags & NVM_FLAGS_V2X) != 0u)
				? SAB_OPEN_SESSION_LOW_LATENCY_MASK : 0U);
		if (err != SAB_SUCCESS_STATUS) {
			nvm_ctx->session_handle = 0u;
			break;
		}

		/* Open the NVM STORAGE session on the selected
		 * security enclave
		 */
		err = sab_open_storage_command(nvm_ctx->phdl,
				nvm_ctx->session_handle,
				&nvm_ctx->storage_handle,
				nvm_ctx->mu_type,
				flags);
		if (err != SAB_SUCCESS_STATUS) {
			nvm_ctx->storage_handle = 0u;
			break;
		}
	} while (false);

	/* Clean-up in case of error. */
	if (err != SAB_SUCCESS_STATUS) {
		nvm_close_session(nvm_ctx);
		//clean nvm_ctx
	}
}

static uint32_t nvm_export_finish_rsp(struct nvm_ctx_st *nvm_ctx_param,
				      uint32_t error)
{
	struct sab_cmd_key_store_export_finish_rsp resp;
	uint32_t ret = SAB_FAILURE_STATUS;
	int32_t len;

	do {
		if (nvm_ctx_param->storage_handle == 0u) {
			break;
		}
		plat_fill_rsp_msg_hdr(&resp.hdr,
				      SAB_STORAGE_EXPORT_FINISH_REQ,
				      (uint32_t) sizeof(struct sab_cmd_key_store_export_finish_rsp),
				      nvm_ctx_param->mu_type);
		if (error == 0u) {
			resp.rsp_code = SAB_SUCCESS_STATUS;
		} else {
			resp.rsp_code = SAB_FAILURE_STATUS;
		}
		resp.storage_handle = nvm_ctx_param->storage_handle;
		len = plat_os_abs_send_mu_message(nvm_ctx_param->phdl,
				(uint32_t *)&resp,
				(uint32_t) sizeof(struct
					sab_cmd_key_store_export_finish_rsp)
				);
		if (len != (int32_t)sizeof(struct
					sab_cmd_key_store_export_finish_rsp)) {
			break;
		}

		/* success. */
		ret = SAB_SUCCESS_STATUS;
	} while (false);

	return ret;
}

static uint32_t nvm_manager_export_chunk(struct nvm_ctx_st *nvm_ctx_param,
					 struct sab_cmd_key_store_chunk_export_msg *msg,
					 int32_t msg_len)
{
	uint32_t err = 0u;
	uint32_t data_len;
	int32_t len = 0;
	struct nvm_chunk_hdr *chunk = NULL;
	struct sab_cmd_key_store_chunk_export_rsp resp;
	struct sab_cmd_key_store_export_finish_msg finish_msg;
	uint64_t plat_addr;
	struct nvm_header_s *blob_hdr;
	uint32_t blob_size = 0u;

	do {
		/* Consistency check of message length. */
		if (msg_len != (int32_t)sizeof(struct sab_cmd_key_store_chunk_export_msg)) {
			break;
		}
		/* Extract length of the blob from the message. */
		blob_size = msg->chunk_size;
		data_len = msg->chunk_size + (uint32_t)sizeof(struct nvm_header_s);

		if ((data_len == 0u) || (data_len > 16u*1024u)) {
			/* Fixing arbitrary maximum blob size to 16k
			 * for sanity checks.
			 */
			break;
		}
		/* Allocate memory for receiving data. */
		chunk = (struct nvm_chunk_hdr *)plat_os_abs_malloc((uint32_t)sizeof(struct nvm_chunk_hdr));

		if (chunk != NULL) {
			chunk->data = plat_os_abs_malloc(data_len + (uint32_t)sizeof(struct nvm_header_s));
			chunk->blob_id = ((uint64_t)(msg->blob_id_ext) << 32u)
					 | (uint64_t)(msg->blob_id);
			chunk->len = data_len;
		}
		/* If allocation failed the response should be sent to platform
		 * with an error code. Process is stopped after.
		 */

		/* Build the response indicating the destination address
		 * to platform.
		 */
		plat_fill_rsp_msg_hdr(&resp.hdr,
				      SAB_STORAGE_CHUNK_EXPORT_REQ,
				      (uint32_t)sizeof(struct sab_cmd_key_store_chunk_export_rsp),
				      nvm_ctx_param->mu_type);

		if ((chunk != NULL) && (chunk->data != NULL)) {
			plat_addr = plat_os_abs_data_buf(nvm_ctx_param->phdl,
					chunk->data + (uint32_t)sizeof(struct nvm_header_s),
					blob_size,
					0u);
			resp.chunk_export_address =
					(uint32_t)(plat_addr & 0xFFFFFFFFu);
			resp.rsp_code = SAB_SUCCESS_STATUS;
		} else {
			resp.chunk_export_address = 0;
			resp.rsp_code = SAB_FAILURE_STATUS;
		}

		len = plat_os_abs_send_mu_message(nvm_ctx_param->phdl,
						  (uint32_t *)&resp,
						  (uint32_t)sizeof(struct sab_cmd_key_store_chunk_export_rsp));

		if (len != (int32_t)sizeof(struct sab_cmd_key_store_chunk_export_rsp)) {
			break;
		}

		if ((chunk == NULL) || (chunk->data == NULL)) {
			break;
		}

		/* Wait for the message from platform indicating that
		 * the data are available at the specified destination.
		 */
		len = plat_os_abs_read_mu_message(nvm_ctx_param->phdl,
						  (uint32_t *)&finish_msg,
						  (uint32_t)sizeof(struct sab_cmd_key_store_export_finish_msg));

		if ((finish_msg.hdr.command != SAB_STORAGE_EXPORT_FINISH_REQ)
			|| (len != (int32_t)sizeof(struct sab_cmd_key_store_export_finish_msg))) {
			break;
		}

		if (finish_msg.export_status == SAB_EXPORT_STATUS_SUCCESS) {

			blob_hdr = (struct nvm_header_s *)chunk->data;
			blob_hdr->size = chunk->len;
			blob_hdr->crc = plat_fetch_msg_crc((uint32_t *)(chunk->data
							     + sizeof(struct nvm_header_s)),
							   chunk->len);
			blob_hdr->blob_id = chunk->blob_id;

			if (plat_os_abs_storage_write_chunk(
						nvm_ctx_param->phdl,
						chunk->data,
						chunk->len,
						chunk->blob_id,
						nvm_ctx_param->nvm_dname)
					!= (int32_t)(chunk->len)) {
				err = 1;
			}
		}

		/* Send success to platform. */
		(void)nvm_export_finish_rsp(nvm_ctx_param, err);

		err = 0u;
	} while (false);

	if (chunk != NULL) {
		plat_os_abs_free(chunk->data);
	}
	plat_os_abs_free(chunk);

	return err;
}

int nvm_manager(uint8_t flags,
		 void **ctx,
		 uint8_t *fname,
		 uint8_t *dname)
{
	int32_t len = 0;
	uint32_t data_len = 0u;
	struct nvm_header_s nvm_hdr;
	uint32_t recv_msg[MAX_RCV_MSG_SIZE / sizeof(uint32_t)];
	struct sab_mu_hdr *hdr = (struct sab_mu_hdr *)recv_msg;
	uint32_t err = 0u;
	uint8_t *data = NULL;
	uint8_t retry = 0;
	struct nvm_ctx_st *nvm_ctx = NULL;
	uint32_t rsp_code;

	if ((strlen(fname) > MAX_FNAME_DNAME_SZ)
		|| (strlen(dname) > MAX_FNAME_DNAME_SZ)) {
		printf("Error: Invalid File or Directory name.\n");
		err = -EIO;

		return err;
	}
	nvm_ctx = (struct nvm_ctx_st *)plat_os_abs_malloc(sizeof(struct nvm_ctx_st));
	if (nvm_ctx == NULL) {
		printf("Error: Insufficient memory.\n");
		err = -ENOMEM;

		return err;
	}

	plat_os_abs_memcpy(nvm_ctx->nvm_fname, fname, NO_LENGTH);
	plat_os_abs_memcpy(nvm_ctx->nvm_dname, dname, NO_LENGTH);

	*ctx = nvm_ctx;

	do {
		retry = 0;

		nvm_ctx->status = NVM_STATUS_STARTING;

		nvm_open_session(flags, nvm_ctx);

		if (nvm_ctx->phdl == NULL) {
			err = 1;
			break;
		}

		/*
		 * Try to read the storage header which length is known.
		 * Then if successful extract the full length and
		 * read the whole storage into an allocated buffer.
		 */
		if (plat_os_abs_storage_read(nvm_ctx->phdl,
					     (uint8_t *)&nvm_hdr,
					     (uint32_t)sizeof(nvm_hdr),
					     nvm_ctx->nvm_fname)
				== (int32_t)sizeof(nvm_hdr)) {

			data_len = nvm_hdr.size + (uint32_t)sizeof(nvm_hdr);
			data = plat_os_abs_malloc(data_len);

			if (data != NULL) {
				if (plat_os_abs_storage_read(nvm_ctx->phdl,
							     data,
							     data_len,
							     nvm_ctx->nvm_fname)
						== (int32_t)data_len) {
					/* In case of error then start anyway
					 * the storage manager process so
					 * platform can create and export a
					 * storage.
					 */
					if (nvm_storage_import(nvm_ctx,
								data,
								data_len)
							!= SAB_SUCCESS_STATUS)
						se_err("Warn: Failure in Master Storage Data Import.\n");
				}
				plat_os_abs_free(data);
				data = NULL;
				len = 0;
			}
		}
		nvm_ctx->status = NVM_STATUS_RUNNING;
		nvm_ctx->next_cmd_id = NEXT_EXPECTED_CMD_NONE;

		/* Infinite loop waiting for platform commands. */
		while (true) {
			/* Receive a message from platform and
			 * process it according its type.
			 */
			plat_os_abs_memset((uint8_t *)recv_msg, 0u, (uint32_t)sizeof(recv_msg));
			len = plat_os_abs_read_mu_message(nvm_ctx->phdl,
							  recv_msg,
							  MAX_RCV_MSG_SIZE);
			if (len < 0) {
				retry = 1;
				/* handle case when platform/V2X are reset */
				plat_os_abs_close_session(nvm_ctx->phdl);
				nvm_ctx->phdl = NULL;
				break;
			}

			switch (hdr->command) {
			case SAB_STORAGE_MASTER_EXPORT_REQ:
				err = process_sab_rcv_send_msg(nvm_ctx,
							       recv_msg,
							       hdr->command,
							       &rsp_code, len,
							       &nvm_ctx->last_data,
							       &nvm_ctx->last_data_sz,
							       &nvm_ctx->next_cmd_id);
				break;
			case SAB_STORAGE_EXPORT_FINISH_REQ:
				err = process_sab_rcv_send_msg(nvm_ctx,
							       recv_msg,
							       hdr->command,
							       &rsp_code, len,
							       &nvm_ctx->last_data,
							       &nvm_ctx->last_data_sz,
							       &nvm_ctx->next_cmd_id);
				break;
			case SAB_STORAGE_CHUNK_EXPORT_REQ:
				err = nvm_manager_export_chunk(nvm_ctx,
							       (struct sab_cmd_key_store_chunk_export_msg *)recv_msg,
							       len);
				break;
			case SAB_STORAGE_CHUNK_GET_REQ:
				err = process_sab_rcv_send_msg(nvm_ctx,
							       recv_msg,
							       hdr->command,
							       &rsp_code, len,
							       &nvm_ctx->last_data,
							       &nvm_ctx->last_data_sz,
							       &nvm_ctx->next_cmd_id);
				break;
			case SAB_STORAGE_CHUNK_GET_DONE_REQ:
				err = process_sab_rcv_send_msg(nvm_ctx,
							       recv_msg,
							       hdr->command,
							       &rsp_code, len,
							       &nvm_ctx->last_data,
							       &nvm_ctx->last_data_sz,
							       &nvm_ctx->next_cmd_id);
				break;
			default:
				err = 1u;
				break;
			}
		}
	} while (retry);

	nvm_ctx->status = NVM_STATUS_STOPPED;

	if (nvm_ctx->phdl != NULL) {
		nvm_close_session(nvm_ctx);
	} else {
		plat_os_abs_free(nvm_ctx);
	}

	*ctx = NULL;
	return err;
}

uint32_t get_nvmd_status(void *ctx)
{
	return ((struct nvm_ctx_st *)ctx)->status;
}

void __attribute__((constructor)) libele_nvm_start()
{
	int msg_type_id;

	se_info("\nlibele_nvm constructor\n");

	init_sab_nvm_msg_engine(SAB_MSG);
}

void __attribute__((destructor)) libele_nvm_end()
{
	se_info("\nlibele_nvm destructor\n");
}
