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
#include "she_platform.h"

#define SECURE_RAM_BASE_ADDRESS_SECURE	0x20800000
#define SECURE_RAM_NVM_OFFSET 0x400
#define MAX_NVM_MSG_SIZE	20


struct seco_nvm_context {
	uintptr_t shared_mem_offset;
	int shared_mem_size;
	uint32_t blob_size;
	she_hdl *hdl;
};


static int seco_nvm_storage_export_init(struct seco_nvm_context *ctx, struct she_cmd_blob_export_init *msg, struct she_rsp_blob_export_init *resp)
{
	ctx->blob_size = msg->blob_size;

	resp->header.ver = MESSAGING_VERSION_2;
	resp->header.size = sizeof(struct she_rsp_blob_export_init) / sizeof(uint32_t);
	resp->header.command = AHAB_SHE_CMD_STORAGE_EXPORT_INIT;
	resp->header.tag = MESSAGING_TAG_RESPONSE;
	resp->rsp_code = AHAB_SUCCESS_IND;

	/* Ask Seco to place the blob at the beginning of the shared memory area dedicated for NVM. */
	resp->load_address_ext = ((SECURE_RAM_BASE_ADDRESS_SECURE + ctx->shared_mem_offset) >> 32) & 0xFFFFFFFF;
	resp->load_address = ((SECURE_RAM_BASE_ADDRESS_SECURE + ctx->shared_mem_offset + SECURE_RAM_NVM_OFFSET) & 0xFFFFFFFF);

	return sizeof(struct she_rsp_blob_export_init);
}


static int seco_nvm_storage_export(struct seco_nvm_context *ctx, struct she_cmd_blob_export *msg, struct she_rsp_blob_export *resp)
{
	seco_storage_write(ctx->hdl, SECURE_RAM_NVM_OFFSET, ctx->blob_size);

	resp->header.ver = MESSAGING_VERSION_2;
	resp->header.size = sizeof(struct she_rsp_blob_export) / sizeof(uint32_t);
	resp->header.command = AHAB_SHE_CMD_STORAGE_EXPORT_REQ;
	resp->header.tag = MESSAGING_TAG_RESPONSE;

	return sizeof(struct she_rsp_blob_export);
}


static int seco_nvm_storage_import(struct seco_nvm_context *ctx, struct she_cmd_blob_import *msg)
{
	int l;
	/* Blob is at the beginning of the secure memory area dedicated for NVM. */
	l = seco_storage_read(ctx->hdl, SECURE_RAM_NVM_OFFSET, ctx->shared_mem_size - SECURE_RAM_NVM_OFFSET);
	if (l == 0)
		return 0; /* No storage found or error reading it. Don't send any message to Seco. */

	msg->header.ver = MESSAGING_VERSION_2;
	msg->header.size = sizeof(struct she_cmd_blob_import) / sizeof(uint32_t);
	msg->header.command = AHAB_SHE_CMD_STORAGE_IMPORT_REQ;
	msg->header.tag = MESSAGING_TAG_RESPONSE;

	msg->load_address_ext = ((SECURE_RAM_BASE_ADDRESS_SECURE + ctx->shared_mem_offset) >> 32) & 0xFFFFFFFF;
	msg->load_address = ((SECURE_RAM_BASE_ADDRESS_SECURE + ctx->shared_mem_offset + SECURE_RAM_NVM_OFFSET) & 0xFFFFFFFF);
	msg->blob_size = l;

	return sizeof(struct she_cmd_blob_import);
}


static void *seco_nvm_thread(void *arg) {

	uint8_t	msg_in[MAX_NVM_MSG_SIZE];
	uint8_t	msg_out[MAX_NVM_MSG_SIZE];
	int msg_len, rsp_len, l;
	struct she_mu_hdr *hdr;
	struct seco_nvm_context *ctx = (struct seco_nvm_context *)arg;

	do {
		msg_len = she_platform_read_mu_message(ctx->hdl, msg_in, MAX_NVM_MSG_SIZE);
		rsp_len = 0;
		if (msg_len > 0) {
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
			}
		}

		if (rsp_len) {
			l = she_platform_send_mu_message(ctx->hdl, msg_out, rsp_len);
		}

	} while (1);


	she_platform_close_session(ctx->hdl);
	return NULL;
}


static struct seco_nvm_context nvm_ctx;

void she_nvm_init(uintptr_t shared_mem_offset, int shared_mem_size) {
	uint32_t msg_len;
	uint8_t	msg_out[MAX_NVM_MSG_SIZE];

	nvm_ctx.shared_mem_offset = shared_mem_offset;
	nvm_ctx.shared_mem_size = shared_mem_size;


	nvm_ctx.hdl = she_platform_open_session(SHE_NVM);

	she_platform_configure_shared_buf(nvm_ctx.hdl, nvm_ctx.shared_mem_offset, nvm_ctx.shared_mem_size);

	msg_len = seco_nvm_storage_import(&nvm_ctx, (struct she_cmd_blob_import *)msg_out);
	if (msg_len) {
		she_platform_send_mu_message(nvm_ctx.hdl, msg_out, msg_len);
	}

	she_platform_create_thread(&seco_nvm_thread, &nvm_ctx);
}