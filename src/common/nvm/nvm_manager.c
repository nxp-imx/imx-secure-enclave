// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2019-2023 NXP
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

#if MT_SAB_STORAGE_KEY_DB_REQ
#include "sab_storage_key_db.h"
#endif

/* Storage import processing. Return 0 on success.  */
static uint32_t nvm_storage_import(struct nvm_ctx_st *nvm_ctx_param,
				   uint8_t *data, uint32_t len)
{
	struct nvm_header_s *blob_hdr;
	uint32_t ret = SAB_FAILURE_STATUS;
	int32_t error;
	uint32_t rsp_code = SAB_FAILURE_STATUS;

	do {
		if (nvm_ctx_param->storage_handle == 0u) {
			break;
		}

		blob_hdr = (struct nvm_header_s *)data;

		/* Sanity check on the provided data. */
		if ((TO_UINT8_T(blob_hdr->size) + NVM_HEADER_SZ) != len)
			break;

		if (plat_fetch_msg_crc((uint32_t *)(data + NVM_HEADER_SZ),
				       blob_hdr->size) != blob_hdr->crc)
			break;

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
	uint32_t rsp_code = SAB_FAILURE_STATUS;
	uint32_t ret;

	if (ctx == NULL) {
		se_err("Error: No active context to close.\n");
		return;
	}

	if (nvm_ctx->phdl != NULL) {
		if (nvm_ctx->storage_handle != 0u) {
			ret = process_sab_msg(nvm_ctx->phdl,
					      nvm_ctx->mu_type,
					      SAB_STORAGE_CLOSE_REQ,
					      MT_SAB_STORAGE_CLOSE,
					      (uint32_t)nvm_ctx->storage_handle,
					      NULL, &rsp_code);
			if (ret != plat_sab_success_tag(nvm_ctx->phdl))
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
			if (PARSE_LIB_ERR_STATUS(ret) != SAB_LIB_SUCCESS)
				se_err("Warn: Failure in Session Close.\n");
			nvm_ctx->session_handle = 0u;
		}

		plat_os_abs_close_session(nvm_ctx->phdl);
		nvm_ctx->phdl = NULL;
	}

	if (nvm_ctx->status != NVM_STATUS_RUNNING)
		plat_os_abs_free(nvm_ctx);
}

static uint32_t nvm_open_session(uint8_t flags, struct nvm_ctx_st *nvm_ctx)
{
	uint32_t err = SAB_FAILURE_STATUS;
	struct plat_mu_params mu_params = {0};
	op_storage_open_args_t *args = NULL;
	open_session_args_t sess_args = {0};
	uint32_t rsp_code = SAB_FAILURE_STATUS;
	uint32_t ret = SAB_FAILURE_STATUS;

	do {
		/* Check if structure is already in use */
		if (nvm_ctx->phdl) {
			err = plat_sab_success_tag(nvm_ctx->phdl);
			break;
		}

		/* Open the Storage session on the MU */
		switch (flags) {
		case NVM_FLAGS_SHE:
			nvm_ctx->mu_type = MU_CHANNEL_PLAT_SHE_NVM;
			break;
		case NVM_FLAGS_V2X_SHE:
			nvm_ctx->mu_type = MU_CHANNEL_V2X_SHE_NVM;
			break;
		case NVM_FLAGS_HSM:
			nvm_ctx->mu_type = MU_CHANNEL_PLAT_HSM_NVM;
			break;
		case NVM_FLAGS_V2X_HSM:
			nvm_ctx->mu_type = MU_CHANNEL_V2X_HSM_NVM;
			break;
		default:
			nvm_ctx->mu_type = MU_CHANNEL_PLAT_HSM_NVM;
			break;
		}

		nvm_ctx->phdl = plat_os_abs_open_mu_channel(nvm_ctx->mu_type,
							    &mu_params);

		if (nvm_ctx->phdl == NULL) {
			break;
		}

		/* Open the SAB session on the selected security enclave */
#ifndef PSA_COMPLIANT
		sess_args.mu_id = mu_params.mu_id;
		sess_args.tz = mu_params.tz;
		sess_args.did = mu_params.did;
#endif
		sess_args.interrupt_idx = mu_params.interrupt_idx;
		sess_args.session_priority = HSM_OPEN_SESSION_PRIORITY_LOW;
		sess_args.operating_mode = ((flags & NVM_FLAGS_V2X) != 0u)
					   ? HSM_OPEN_SESSION_LOW_LATENCY_MASK : 0U;

		err = process_sab_msg(nvm_ctx->phdl,
				      nvm_ctx->mu_type,
				      SAB_SESSION_OPEN_REQ,
				      MT_SAB_SESSION,
				      (uint32_t)sess_args.session_hdl,
				      &sess_args, &rsp_code);
		ret = rsp_code;
		if (PARSE_LIB_ERR_STATUS(err) != SAB_LIB_SUCCESS) {
			err = SAB_FAILURE_STATUS;
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
		if (err != plat_sab_success_tag(nvm_ctx->phdl)) {
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
	if (err == SAB_FAILURE_STATUS) {
		if (nvm_ctx->session_handle)
			nvm_close_session(nvm_ctx);
		//clean nvm_ctx
	}

	return ret;
}

uint32_t nvm_manager(uint8_t flags,
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

#if MT_SAB_STORAGE_KEY_DB_REQ
	for (int i = 0; i < MAX_KEY_STORE; i++) {
		/*
		 * Key store ID == 0 is a valid ID. Database is not in used if
		 * both file descriptor are negative
		 */
		nvm_ctx->key_db[i].persistent_tmp_fd = -1;
		nvm_ctx->key_db[i].volatile_fd = -1;
	}
#endif

	*ctx = nvm_ctx;

	do {
		retry = 0;

		nvm_ctx->status = NVM_STATUS_STARTING;

		if (nvm_open_session(flags, nvm_ctx) == SAB_FAILURE_STATUS) {
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
					     NVM_HEADER_SZ,
					     nvm_ctx->nvm_fname)
					     == NVM_HEADER_SZ) {

			data_len = TO_UINT8_T(nvm_hdr.size) + NVM_HEADER_SZ;
			data = plat_os_abs_malloc(data_len);

			if (data != NULL) {
				if (plat_os_abs_storage_read(nvm_ctx->phdl,
							     data,
							     data_len,
							     nvm_ctx->nvm_fname)
							     == data_len) {
					/* In case of error then start anyway
					 * the storage manager process so
					 * platform can create and export a
					 * storage.
					 */
					if (nvm_storage_import(nvm_ctx,
								data,
								data_len)
						!= plat_sab_success_tag(nvm_ctx->phdl))
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
		while (true && (nvm_ctx->status != NVM_STATUS_STOPPED)) {
			/* Receive a message from platform and
			 * process it according its type.
			 */

			err = process_sab_rcv_send_msg(nvm_ctx,
						       &nvm_ctx->last_data,
						       &nvm_ctx->last_data_sz,
						       &nvm_ctx->prev_cmd_id,
						       &nvm_ctx->next_cmd_id);
			if (err == SAB_READ_FAILURE_RATING &&
			    nvm_ctx->status == NVM_STATUS_RUNNING) {
				retry = 1;
				/* handle case when platform/V2X are reset */
				nvm_close_session(nvm_ctx);
				nvm_ctx->phdl = NULL;
				break;
			}
		}
	} while (retry);

	if (nvm_ctx) {
		if (nvm_ctx->status == NVM_STATUS_STOPPED) {
			/**
			 * If NVM status is stopped, means some valid case
			 * was handled for stopping NVM and status was set
			 * accordingly.
			 */
			err = 0;
		} else {
			nvm_ctx->status = NVM_STATUS_STOPPED;
		}

#if MT_SAB_STORAGE_KEY_DB_REQ
		/* Close all opened key database files */
		storage_close_key_db_fd(nvm_ctx->key_db);
#endif

		if (nvm_ctx->phdl)
			nvm_close_session(nvm_ctx);
		else
			plat_os_abs_free(nvm_ctx);
	}

	*ctx = NULL;
	return err;
}

uint32_t get_nvmd_status(void *ctx)
{
	return ((struct nvm_ctx_st *)ctx)->status;
}

void set_nvmd_status_stop(void *ctx)
{
	((struct nvm_ctx_st *)ctx)->status = NVM_STATUS_STOPPED;
}

void __attribute__((constructor)) libele_nvm_start()
{
	se_info("\nlibele_nvm constructor\n");

	init_sab_nvm_msg_engine(SAB_MSG);
}

void __attribute__((destructor)) libele_nvm_end()
{
	se_info("\nlibele_nvm destructor\n");
}
