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
#include "sab_storage_open.h"
#include "internal/hsm_session.h"

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
	op_storage_open_args_t *args = NULL;
	uint32_t  rsp_code;
	uint32_t ret = SAB_FAILURE_STATUS;

	if (ctx == NULL) {
		printf("Error: No active context to close.\n");
		return;
	}

	if (nvm_ctx->phdl != NULL) {
		if (nvm_ctx->storage_handle != 0u) {
			ret = process_sab_msg(nvm_ctx->phdl,
					      nvm_ctx->mu_type,
					      SAB_STORAGE_CLOSE_REQ,
					      MT_SAB_STORAGE_CLOSE,
					      (uint32_t)nvm_ctx->storage_handle,
					      args, &rsp_code);
			if (rsp_code != SAB_SUCCESS_STATUS)
				se_err("Warn: Failure in Storage Close.\n");
			nvm_ctx->storage_handle = 0u;
		}
		if (nvm_ctx->session_handle != 0u) {
			ret = process_sab_msg(nvm_ctx->phdl,
					      nvm_ctx->mu_type,
					      SAB_SESSION_CLOSE_REQ,
					      MT_SAB_SESSION,
					      nvm_ctx->session_handle,
					      NULL, &rsp_code);
			if (ret != SAB_SUCCESS_STATUS)
				se_err("Warn: Failure in Session Close.\n");
			nvm_ctx->session_handle = 0u;
		}

		plat_os_abs_close_session(nvm_ctx->phdl);
		nvm_ctx->phdl = NULL;
	}

	plat_os_abs_free(nvm_ctx);
}

static int nvm_open_session(uint8_t flags, struct nvm_ctx_st *nvm_ctx)
{
	uint32_t err = SAB_FAILURE_STATUS;
	struct plat_mu_params mu_params;
	op_storage_open_args_t *args = NULL;
	open_session_args_t sess_args;
	uint32_t *storage_handle = NULL;
	uint32_t  rsp_code;
	uint32_t ret = SAB_FAILURE_STATUS;

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
		sess_args.mu_id = mu_params.mu_id;
		sess_args.interrupt_idx = mu_params.interrupt_idx;
		sess_args.tz = mu_params.tz;
		sess_args.did = mu_params.did;
		sess_args.session_priority = SAB_OPEN_SESSION_PRIORITY_LOW;
		sess_args.operating_mode = ((flags & NVM_FLAGS_V2X) != 0u)
					   ? SAB_OPEN_SESSION_LOW_LATENCY_MASK : 0U;

		err = process_sab_msg(nvm_ctx->phdl,
				      nvm_ctx->mu_type,
				      SAB_SESSION_OPEN_REQ,
				      MT_SAB_SESSION,
				      (uint32_t)sess_args.session_hdl,
				      &sess_args, &rsp_code);
		ret = rsp_code;
		if (err != SAB_SUCCESS_STATUS) {
			nvm_ctx->session_handle = 0u;
			break;
		}

		nvm_ctx->session_handle = sess_args.session_hdl;
		/* Open the NVM STORAGE session on the selected
		 * security enclave
		 */
		args = (op_storage_open_args_t *)
			plat_os_abs_malloc((uint32_t)sizeof(op_storage_open_args_t));
		if (args == NULL)
			break;

		plat_os_abs_memset((uint8_t *)args, 0u, (uint32_t)sizeof(op_storage_open_args_t));
		args->flags = flags;

		err = process_sab_msg(nvm_ctx->phdl,
					nvm_ctx->mu_type,
					SAB_STORAGE_OPEN_REQ,
					MT_SAB_STORAGE_OPEN,
					(uint32_t)nvm_ctx->session_handle,
					args, &rsp_code);
		ret = rsp_code;
		if (err != SAB_SUCCESS_STATUS) {
			nvm_ctx->storage_handle = 0u;
			break;
		} else {
			nvm_ctx->storage_handle = args->storage_handle;
		}
	} while (false);

	if (args) {
		plat_os_abs_free(args);
		args = NULL;
	}

	/* Clean-up in case of error. */
	if (err != SAB_SUCCESS_STATUS) {
		nvm_close_session(nvm_ctx);
		//clean nvm_ctx
	}

	return ret;
}

int nvm_manager(uint8_t flags,
		 void **ctx,
		 uint8_t *fname,
		 uint8_t *dname)
{
	int32_t len = 0;
	uint32_t data_len = 0u;
	struct nvm_header_s nvm_hdr;
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

		if (nvm_open_session(flags, nvm_ctx) != SAB_SUCCESS_STATUS)
			se_err("Warn: Failure in Storage Open.\n");

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
		nvm_ctx->prev_cmd_id = NEXT_EXPECTED_CMD_NONE;
		nvm_ctx->next_cmd_id = NEXT_EXPECTED_CMD_NONE;

		/* Infinite loop waiting for platform commands. */
		while (true) {
			/* Receive a message from platform and
			 * process it according its type.
			 */

			err = process_sab_rcv_send_msg(nvm_ctx,
						       &nvm_ctx->last_data,
						       &nvm_ctx->last_data_sz,
						       &nvm_ctx->prev_cmd_id,
						       &nvm_ctx->next_cmd_id);
			if (err == SAB_READ_FAILURE_RATING) {
				retry = 1;
				/* handle case when platform/V2X are reset */
				plat_os_abs_close_session(nvm_ctx->phdl);
				nvm_ctx->phdl = NULL;
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
