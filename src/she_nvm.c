/*
 * Copyright 2019 NXP
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

#include "she_msg.h"
#include "she_nvm.h"
#include "she_platform.h"

#define SECURE_RAM_BASE_ADDRESS_SECURE	0x20800000
#define SECURE_RAM_NVM_OFFSET 0x400
#define MAX_NVM_MSG_SIZE	20


struct seco_nvm_context {
	uintptr_t shared_mem_offset;
	uint32_t shared_mem_size;
	uint32_t blob_size;
	struct she_platform_hdl *hdl;
};


/* Storage export init command processing. */
static uint32_t seco_nvm_storage_export_init(struct seco_nvm_context *ctx, struct she_cmd_blob_export_init *msg, struct she_rsp_blob_export_init *resp)
{
	/* Build the response. */
	she_fill_rsp_msg_hdr(&resp->hdr, AHAB_SHE_CMD_STORAGE_EXPORT_INIT, sizeof(struct she_rsp_blob_export_init));

	/* Check if there is enough space in allocated buffer. */
	if (msg->blob_size < ctx->shared_mem_size - SECURE_RAM_NVM_OFFSET) {
		/* Place the blob at the beginning of the shared memory area dedicated for NVM. */
		resp->rsp_code = AHAB_SUCCESS_IND;
		resp->load_address_ext = ((SECURE_RAM_BASE_ADDRESS_SECURE + ctx->shared_mem_offset) >> 32) & 0xFFFFFFFF;
		resp->load_address = ((SECURE_RAM_BASE_ADDRESS_SECURE + ctx->shared_mem_offset + SECURE_RAM_NVM_OFFSET) & 0xFFFFFFFF);
		/* Fill blob size in context for later processing. */
		ctx->blob_size = msg->blob_size;
	} else {
		/* Not enough place. report error to Seco. */
		resp->rsp_code = AHAB_FAILURE_IND;
		resp->load_address_ext = 0;
		resp->load_address = 0;
		ctx->blob_size = 0;
	}

	return sizeof(struct she_rsp_blob_export_init);
}

/* Storage export command processing. */
static uint32_t seco_nvm_storage_export(struct seco_nvm_context *ctx, struct she_cmd_blob_export *msg, struct she_rsp_blob_export *resp)
{
	uint32_t l = 0;

	/* Write the data to the storage. Blob size was received in previous "storage_export_init" message.*/
	if (ctx->blob_size > 0) {
		l = seco_storage_write(ctx->hdl, SECURE_RAM_NVM_OFFSET, ctx->blob_size);
	}

	/* Build the response. */
	she_fill_rsp_msg_hdr(&resp->hdr, AHAB_SHE_CMD_STORAGE_EXPORT_REQ, sizeof(struct she_rsp_blob_export));

	/* Success only if there was data to write and all data were written. */
	if ((l != 0) && (l == ctx->blob_size)) {
		resp->rsp_code = AHAB_SUCCESS_IND;
	} else {
		resp->rsp_code = AHAB_FAILURE_IND;
	}

	return sizeof(struct she_rsp_blob_export);
}

/* Storage import processing. Return 0 on success.  */
static int32_t seco_nvm_storage_import(struct seco_nvm_context *ctx)
{
	struct she_cmd_blob_import msg;
	struct she_rsp_blob_import rsp;

	uint32_t blob_size;
	uint32_t len = 0;
	int32_t error = -1;

	do {
		/* Place blob from nvm at the beginning of the secure memory area dedicated for NVM. */
		blob_size = seco_storage_read(ctx->hdl, SECURE_RAM_NVM_OFFSET, ctx->shared_mem_size - SECURE_RAM_NVM_OFFSET);
		if (blob_size == 0) {
			/* No storage found or error while reading it. Don't send the command to Seco. */
			break;
		}

		/* Prepare command message. */
		she_fill_cmd_msg_hdr(&msg.hdr, AHAB_SHE_CMD_STORAGE_IMPORT_REQ, sizeof(struct she_cmd_blob_import));
		msg.load_address_ext = ((SECURE_RAM_BASE_ADDRESS_SECURE + ctx->shared_mem_offset) >> 32) & 0xFFFFFFFF;
		msg.load_address = ((SECURE_RAM_BASE_ADDRESS_SECURE + ctx->shared_mem_offset + SECURE_RAM_NVM_OFFSET) & 0xFFFFFFFF);
		msg.blob_size = blob_size;

		/* Send the message to Seco. */
		len = she_platform_send_mu_message(ctx->hdl, (char *)&msg, sizeof(struct she_cmd_blob_import));
		if (len != sizeof(struct she_cmd_blob_import)) {
			break;
		}

		/* Read the response. */
		len = she_platform_read_mu_message(ctx->hdl, (char *)&rsp, sizeof(struct she_rsp_blob_import));
		if (len != sizeof(struct she_rsp_blob_import)) {
			break;
		}

		/* Check error status reported by Seco. */
		if (rsp.rsp_code != AHAB_SUCCESS_IND) {
			break;
		}

		/* Success. */
		error = 0;
	} while (0);

	return error;
}

/* Thread waiting for messages on the NVM MU and processing them in loop. */
static void *seco_nvm_thread(void *arg) {

	uint8_t	msg_in[MAX_NVM_MSG_SIZE];
	uint8_t	msg_out[MAX_NVM_MSG_SIZE];
	uint32_t msg_len, rsp_len;
	struct she_mu_hdr *hdr;
	struct seco_nvm_context *ctx = (struct seco_nvm_context *)arg;

	do {
		/* Wait message on the NVM MU (blocking read). */
		msg_len = she_platform_read_mu_message(ctx->hdl, msg_in, MAX_NVM_MSG_SIZE);

		if (msg_len == 0) {
			continue;
		}

		rsp_len = 0;
		/* Triage the message based on the command ID from the header. */
		hdr = (struct she_mu_hdr *)&msg_in[0];
		switch (hdr->command) {
			case AHAB_SHE_CMD_STORAGE_EXPORT_INIT:
			rsp_len = seco_nvm_storage_export_init(ctx, (struct she_cmd_blob_export_init *)msg_in,
						(struct she_rsp_blob_export_init *)msg_out);
			break;

			case AHAB_SHE_CMD_STORAGE_EXPORT_REQ:
			rsp_len = seco_nvm_storage_export(ctx, (struct she_cmd_blob_export *)msg_in,
						(struct she_rsp_blob_export *)msg_out);
			break;

			case AHAB_SHE_CMD_STORAGE_IMPORT_REQ:
				/*'This is the response.*/
				//TODO: handle error.
			break;

			default:
			/* Unknown command: skip. */
			break;
		}

		/* If there is a response to be sent to Seco then write it on the MU. */
		if (rsp_len) {
			(void)she_platform_send_mu_message(ctx->hdl, msg_out, rsp_len);
		}

	} while (1);

	/* Should not come here for now ... */
	she_platform_close_session(ctx->hdl);
	free(ctx);
	return NULL;
}


/* Init of the NVM storage manager. */
int32_t she_nvm_init(uint32_t shared_mem_offset, uint32_t shared_mem_size) {
	uint32_t msg_len, l;
	struct seco_nvm_context *nvm_ctx = NULL;
	int32_t error = -1;

	do {
		/* Prepare the context to be passed to the thread function. */
		nvm_ctx = malloc(sizeof(struct seco_nvm_context));
		if (!nvm_ctx) {
			break;
		}
		nvm_ctx->shared_mem_offset = shared_mem_offset;
		nvm_ctx->shared_mem_size = shared_mem_size;

		/* Open the SHE NVM session. */
		nvm_ctx->hdl = she_platform_open_session(SHE_NVM);
		if (!nvm_ctx->hdl) {
			break;
		}

		/* map the shared buffer. */
		error = she_platform_configure_shared_buf(nvm_ctx->hdl, nvm_ctx->shared_mem_offset, nvm_ctx->shared_mem_size);
		if (error) {
			break;
		}

		/* Try to import the NVM storage. */
		error = seco_nvm_storage_import(nvm_ctx);
		// TODO: Handle errors. (currently Seco can generate himself a fake storage if we cannot provide it from here.)

		/* Start the background thread waiting for NVM commands from Seco. */
		error = she_platform_create_thread(&seco_nvm_thread, nvm_ctx);
	} while (0);

	/* error clean-up. */
	if (error && nvm_ctx) {
		if (nvm_ctx->hdl) {
			she_platform_close_session(nvm_ctx->hdl);
		}
		free(nvm_ctx);
	}

	return error;
}