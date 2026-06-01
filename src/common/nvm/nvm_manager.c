// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2019-2026 NXP
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
#include "nvm_blob_conversion.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

#define SOC_IMX8DXL	0xe
uint16_t g_soc_id;
uint8_t g_nvm_header_sz;

/* Storage import processing. Return 0 on success.  */
static uint32_t nvm_storage_import(struct nvm_ctx_st *nvm_ctx_param,
				   uint8_t *data, uint32_t len)
{
	struct nvm_header_s *blob_hdr;
	uint32_t ret = SAB_FAILURE_STATUS;
	uint32_t error;
	uint32_t rsp_code = SAB_FAILURE_STATUS;

	do {
		if (nvm_ctx_param->storage_handle == 0u) {
			break;
		}

		blob_hdr = (struct nvm_header_s *)data;

		/* Sanity check on the provided data. */
		if (blob_hdr->size != len)
			break;

		if (plat_fetch_msg_crc((uint32_t *)BLOB_START_ADDR(data, g_nvm_header_sz),
				       BLOB_LEN(blob_hdr->size, g_nvm_header_sz))
		    != blob_hdr->crc) {
			se_log_error("blob CRC validation failed\n");
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
	uint16_t soc_rev;
	uint8_t board_type;

	do {
		/* Check if structure is already in use */
		if (nvm_ctx->phdl) {
			err = plat_sab_success_tag(nvm_ctx->phdl);
			break;
		}

		nvm_ctx->mu_type = flags;
		nvm_ctx->phdl = plat_os_abs_open_mu_channel(nvm_ctx->mu_type,
							    &mu_params);

		if (nvm_ctx->phdl == NULL) {
			break;
		}

		/* Open the SAB session on the selected security enclave */
		sess_args.mu_type = nvm_ctx->mu_type;
#ifndef PSA_COMPLIANT
		sess_args.mu_id = mu_params.mu_id;
		sess_args.tz = mu_params.tz;
		sess_args.did = mu_params.did;
#endif
		sess_args.interrupt_idx = mu_params.interrupt_idx;

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

		/* Zeroth bit in the flags, denotes:-
		 * 0: HSM_STORAGE
		 * 1: SHE_STORAGE; MU_DEBUG is added to support SHE NVM on DEBUG MU
		 */
		if (((flags & MU_TYPE_MASK) >> 3) == MU_SHE ||
		    ((flags & MU_TYPE_MASK) >> 3) == MU_DEBUG)
			args->flags = 1;

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

		/*
		 * Fill SOC ID
		 */
		ret = plat_os_abs_get_soc_info(nvm_ctx->phdl,
					       &g_soc_id,
					       &soc_rev,
					       &board_type);
		if (ret != PLAT_SUCCESS)
			break;
	} while (false);

	if (args)
		plat_os_abs_free(args);

	/* Clean-up in case of error. */
	if (err == SAB_FAILURE_STATUS) {
		if (nvm_ctx->session_handle)
			nvm_close_session(nvm_ctx);
		//clean nvm_ctx
	}

	return ret;
}

bool is_flag_supported(uint8_t flags)
{
	if (flags == HSM_NVM ||
	    flags == SHE_NVM ||
	    flags == V2X_SHE_NVM ||
	    flags == V2X_SHE1_NVM ||
	    flags == V2X_HSM_NVM ||
	    flags == V2X_SHE_DEBUG_MU_NVM)
		return true;
	else
		return false;
}

static uint32_t nvm_storage_import_helper(struct nvm_ctx_st *nvm_ctx,
					  uint32_t nvm_hdr_sz_field_value)
{
	uint32_t ret = SAB_LIB_SUCCESS;
	uint8_t *data;
	uint32_t data_len;
#ifdef PSA_COMPLIANT
	struct nvm_header_s *nvm_hdr;
#endif
	data_len = nvm_hdr_sz_field_value;
	if ((data_len == 0U || data_len < sizeof(struct nvm_header_s)))
		return SAB_LIB_ERROR;

	data = plat_os_abs_malloc(data_len);
	if (!data)
		return SAB_LIB_ERROR;

	if (plat_os_abs_storage_read(nvm_ctx->phdl,
				     data,
				     data_len,
				     nvm_ctx->nvm_fname)
			!= data_len) {
		ret = SAB_LIB_ERROR;
		goto exit;
	}
#ifdef PSA_COMPLIANT
	/* In case of checking for v1 format version, need below
	 * modification in the NVM blob header buffer, so that
	 * the master blob can be parsed successfully with the
	 * v2 parsing rules.
	 */
	if (g_nvm_header_sz == NVM_HEADER_SZ_V1) {
		nvm_hdr = (struct nvm_header_s *)data;
		if (nvm_hdr->size > (UINT32_MAX - g_nvm_header_sz) ||
		    (nvm_hdr->size != (data_len - g_nvm_header_sz))) {
			ret = SAB_LIB_ERROR;
			goto exit;
		}
		nvm_hdr->size += g_nvm_header_sz;
	}
#endif
	/* In case of error then start anyway
	 * the storage manager process so
	 * platform can create and export a
	 * storage.
	 */
	if (nvm_storage_import(nvm_ctx,
			       data,
			       data_len)
			!= plat_sab_success_tag(nvm_ctx->phdl)) {
		ret = SAB_FAILURE_STATUS;
		se_err("Warn: Failure in Master Storage Data Import.\n");
	}
exit:
	plat_os_abs_free(data);
	return ret;
}

static uint32_t do_nvm_import_n_blob_conversion(struct nvm_ctx_st *nvm_ctx,
						uint32_t nvm_hdr_sz_field_value)
{
	uint32_t ret;
#ifdef PSA_COMPLIANT
	uint8_t blob_version_target;
	uint8_t blob_version_present;
	uint32_t adjusted_size;

	/* Identify the existing NVM blob format version:
	 *   - First consider the storage master file to be in latest format
	 *     (version 2) and parse according to perform Storage Import operation.
	 *   - If failed with first consideration, then perform the same process
	 *     with older blob format (version 1) parsing rules.
	 *
	 * The passing case will help identify the format version of existing
	 * NVM blobs.
	 */

	/* Check v2 format for the existing NVM storage master blob */
	g_nvm_header_sz = NVM_HEADER_SZ_V2;

	ret = nvm_storage_import_helper(nvm_ctx, nvm_hdr_sz_field_value);
	if (ret == SAB_LIB_SUCCESS) {
		printf("\nNVM storage master import: v2 success\n");
		goto out;
	} else if (ret == SAB_FAILURE_STATUS) {
		printf("\nNVM storage master import: v2 failed\n");
	} else {
		printf("\nNVM storage master import: v2 lib error\n");
	}

	/* Check v1 format for the existing NVM storage master blob */
	g_nvm_header_sz = NVM_HEADER_SZ_V1;

	if (nvm_hdr_sz_field_value > (UINT32_MAX - g_nvm_header_sz)) {
		printf("Error: NVM header size calculation would overflow\n");
		ret = SAB_LIB_ERROR;
		goto out;
	}

	adjusted_size = nvm_hdr_sz_field_value + g_nvm_header_sz;

	ret = nvm_storage_import_helper(nvm_ctx, adjusted_size);
	if (ret == SAB_LIB_SUCCESS) {
		printf("\nNVM storage master import: v1 success\n");
		goto out;
	} else if (ret == SAB_FAILURE_STATUS) {
		printf("\nNVM storage master import: v1 failed\n");
	} else {
		printf("\nNVM storage master import: v1 lib error\n");
	}

out:
	blob_version_present = g_nvm_header_sz;
	blob_version_target = nvm_get_current_header_version();

	/* Check if existing blobs format version mismatch with the current
	 * supported version, and blobs need to be migrated accordingly to work
	 * with current blob format parsing rules.
	 */
	if (ret == SAB_LIB_SUCCESS && blob_version_present != blob_version_target) {
		ret = nvm_blobs_format_conversion(nvm_ctx,
						  blob_version_present,
						  blob_version_target);
		if (ret)
			printf("\nError: failed to convert NVM blobs format.\n");
	}
#else
	g_nvm_header_sz = NVM_HEADER_SZ;
	ret = nvm_storage_import_helper(nvm_ctx, nvm_hdr_sz_field_value);
#endif
	return ret;
}

uint32_t nvm_manager(uint8_t flags,
		     void **ctx,
		     uint8_t *fname,
		     uint8_t *dname)
{
	struct nvm_header_s nvm_hdr;
	uint32_t err = 0u;
	uint8_t retry = 0;
	struct nvm_ctx_st *nvm_ctx = NULL;

	if (!is_flag_supported(flags))
		return -EINVAL;

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

	plat_os_abs_memset((uint8_t *)nvm_ctx, 0, sizeof(struct nvm_ctx_st));
	plat_os_abs_memcpy(nvm_ctx->nvm_fname, fname, strlen(fname));
	plat_os_abs_memcpy(nvm_ctx->nvm_dname, dname, strlen(dname));

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
			/* For NVM storage master import process,
			 * check if the existing NVM blobs need conversion to
			 * the latest blob format, decide on the basis on the
			 * NVM storage master file and proceed accordingly.
			 */
			do_nvm_import_n_blob_conversion(nvm_ctx, nvm_hdr.size);
		}

		err = plat_os_abs_set_mu_chnl_as_nvm(nvm_ctx->mu_type,
						     nvm_ctx->phdl);
		if (err)
			break;

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
				/* handle case when platform/V2X are reset */
				printf("Platform/V2X are reset\n");
				if (g_soc_id == SOC_IMX8DXL) {
					retry = 1;
					nvm_close_session(nvm_ctx);
					nvm_ctx->phdl = NULL;
					break;
				}
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
