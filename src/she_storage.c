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
#include "she_storage.h"
#include <string.h>
#include "messaging.h"

#define MAX_NVM_MSG_SIZE    10
#define MAX_BLOB_SIZE 0x1000u

#define SHE_STORAGE_DEFAULT_DID             0x0u
#define SHE_STORAGE_DEFAULT_TZ              0x0u
#define SHE_STORAGE_DEFAULT_MU              0x1u
#define SHE_STORAGE_DEFAULT_INTERRUPT_IDX   0x0u
#define SHE_STORAGE_DEFAULT_PRIORITY        0x0u
#define SHE_STORAGE_DEFAULT_OPERATING_MODE  0x0u

struct she_storage_context {
    uint32_t blob_size;
    uint8_t *blob_buf;
    struct she_platform_hdl *hdl;
    uint32_t session_handle;
};

struct seco_nvm_header_s {
    uint32_t size;
    uint32_t crc;
};

/* Storage export init command processing. */
static int32_t she_storage_export_init(struct she_storage_context *ctx, struct she_cmd_blob_export_init_msg *msg, struct she_cmd_blob_export_init_rsp *resp)
{
    uint64_t seco_addr;

    /* Build the response. */
    she_fill_rsp_msg_hdr(&resp->hdr, AHAB_SHE_CMD_STORAGE_EXPORT_INIT, (uint32_t)sizeof(struct she_cmd_blob_export_init_rsp));

    if (ctx->blob_buf != NULL) {
        /* a previous storage export transaction may have failed.*/
        free(ctx->blob_buf);
        ctx->blob_buf = NULL;
        ctx->blob_size = 0;
    }

    do {
        /* Initialize response with error as default. */
        resp->rsp_code = AHAB_FAILURE_IND;
        resp->load_address_ext = 0;
        resp->load_address = 0;
        ctx->blob_size = 0;

        if (msg->blob_size > MAX_BLOB_SIZE) {
            break;
        }

        ctx->blob_buf = malloc(msg->blob_size + sizeof(struct seco_nvm_header_s));
        ctx->blob_size = msg->blob_size;
        if (ctx->blob_buf == NULL) {
            break;
        }

        seco_addr = she_platform_data_buf(ctx->hdl, ctx->blob_buf + sizeof(struct seco_nvm_header_s), msg->blob_size, DATA_BUF_USE_SEC_MEM);
        if (seco_addr == 0u) {
            free(ctx->blob_buf);
            ctx->blob_buf = NULL;
            ctx->blob_size = 0;
            break;
        }
        resp->load_address_ext = (uint32_t)((seco_addr >> 32u) & 0xFFFFFFFFu);
        resp->load_address = (uint32_t)(seco_addr & 0xFFFFFFFFu);
        resp->rsp_code = AHAB_SUCCESS_IND;
    } while (false);

    return (int32_t)sizeof(struct she_cmd_blob_export_init_rsp);
}

/* Storage export command processing. */
static int32_t she_storage_export(struct she_storage_context *ctx, struct she_cmd_blob_export_msg *msg, struct she_cmd_blob_export_rsp *resp)
{
    int32_t l;
    struct seco_nvm_header_s *blob_hdr;

    resp->rsp_code = AHAB_FAILURE_IND;
    /* Write the data to the storage. Blob size was received in previous "storage_export_init" message.*/
    if (ctx->blob_buf != NULL) {
        blob_hdr = (struct seco_nvm_header_s *)ctx->blob_buf;
        blob_hdr->size = ctx->blob_size;
        blob_hdr->crc = she_platform_crc(ctx->blob_buf + sizeof(struct seco_nvm_header_s), ctx->blob_size);

        l = she_platform_storage_write(ctx->hdl, ctx->blob_buf, ctx->blob_size + (uint32_t)sizeof(struct seco_nvm_header_s));

        if (l == (int32_t)ctx->blob_size + (int32_t)sizeof(struct seco_nvm_header_s)) {
            resp->rsp_code = AHAB_SUCCESS_IND;
        }

        free(ctx->blob_buf);
        ctx->blob_buf = NULL;
        ctx->blob_size = 0;
    }

    /* Build the response. */
    she_fill_rsp_msg_hdr(&resp->hdr, AHAB_SHE_CMD_STORAGE_EXPORT_REQ, (uint32_t)sizeof(struct she_cmd_blob_export_rsp));

    return (int32_t)sizeof(struct she_cmd_blob_export_rsp);
}

/* Storage import processing. Return 0 on success.  */
static int32_t she_storage_import(struct she_storage_context *ctx)
{
    struct she_cmd_blob_import_msg msg;
    struct she_cmd_blob_import_rsp rsp;
    uint64_t seco_addr;
    struct seco_nvm_header_s blob_hdr;

    uint8_t *blob_buf = NULL;
    int32_t len = 0;
    int32_t error = -1;

    do {
        len = she_platform_storage_read(ctx->hdl, (uint8_t *)&blob_hdr, (uint32_t)sizeof(struct seco_nvm_header_s));
        if (len != (int32_t)sizeof(struct seco_nvm_header_s)) {
            break;
        }

        blob_buf = malloc(blob_hdr.size + sizeof(struct seco_nvm_header_s));
        if (blob_buf == NULL) {
            break;
        }

        len = she_platform_storage_read(ctx->hdl, blob_buf, blob_hdr.size  + (uint32_t)sizeof(struct seco_nvm_header_s));
        if (len != (int32_t)blob_hdr.size + (int32_t)sizeof(struct seco_nvm_header_s)) {
            break;
        }

        if (she_platform_crc(blob_buf + sizeof(struct seco_nvm_header_s), blob_hdr.size) != blob_hdr.crc) {
            break;
        }

        seco_addr = she_platform_data_buf(ctx->hdl, blob_buf + sizeof(struct seco_nvm_header_s), blob_hdr.size, DATA_BUF_IS_INPUT | DATA_BUF_USE_SEC_MEM);

        /* Prepare command message. */
        she_fill_cmd_msg_hdr(&msg.hdr, AHAB_SHE_CMD_STORAGE_IMPORT_REQ, (uint32_t)sizeof(struct she_cmd_blob_import_msg));
        msg.load_address_ext = (uint32_t)((seco_addr >> 32u) & 0xFFFFFFFFu);
        msg.load_address = (uint32_t)(seco_addr & 0xFFFFFFFFu);
        msg.blob_size = blob_hdr.size;

        /* Send the message to Seco. */
        len = she_platform_send_mu_message(ctx->hdl, (uint32_t *)&msg, (uint32_t)sizeof(struct she_cmd_blob_import_msg));
        if (len != (int32_t)sizeof(struct she_cmd_blob_import_msg)) {
            break;
        }

        /* Read the response. */
        len = she_platform_read_mu_message(ctx->hdl, (uint32_t *)&rsp, (uint32_t)sizeof(struct she_cmd_blob_import_rsp));
        if (len != (int32_t)sizeof(struct she_cmd_blob_import_rsp)) {
            break;
        }

        /* Check error status reported by Seco. */
        if (rsp.rsp_code != AHAB_SUCCESS_IND) {
            break;
        }

        /* Success. */
        error = 0;
    } while (false);

    if (blob_buf != NULL) {
        free(blob_buf);
    }
    return error;
}


static int32_t she_storage_setup_shared_buffer(struct she_storage_context *ctx)
{
    int32_t err = -1;
    uint32_t shared_buf_offset, shared_buf_size;

    do {

        if (she_get_shared_buffer(ctx->hdl, ctx->session_handle, &shared_buf_offset, &shared_buf_size) != ERC_NO_ERROR) {
            break;
        }

        /* Configure the shared buffer. and start the NVM manager. */
        err = she_platform_configure_shared_buf(ctx->hdl, shared_buf_offset, shared_buf_size);
        if (err != 0) {
            break;
        }

    } while(false);

    return err;
}


/* Thread waiting for messages on the NVM MU and processing them in loop. */
static void *she_storage_thread(void *arg)
{
    uint32_t msg_in[MAX_NVM_MSG_SIZE];
    uint32_t msg_out[MAX_NVM_MSG_SIZE];
    int32_t msg_len, rsp_len;
    struct she_mu_hdr *hdr;
    struct she_storage_context *ctx = (struct she_storage_context *)arg;

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
            rsp_len = she_storage_export_init(ctx, (struct she_cmd_blob_export_init_msg *)msg_in,
                        (struct she_cmd_blob_export_init_rsp *)msg_out);
            break;

            case AHAB_SHE_CMD_STORAGE_EXPORT_REQ:
            rsp_len = she_storage_export(ctx, (struct she_cmd_blob_export_msg *)msg_in,
                        (struct she_cmd_blob_export_rsp *)msg_out);
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
        if (rsp_len > 0) {
            msg_len = she_platform_send_mu_message(ctx->hdl, msg_out, (uint32_t)rsp_len);
            if (msg_len != rsp_len) {
                /* error while sending the message: exit */
                break;
            }
        }

    } while (true);

    /* Should not come here for now ... */
    she_platform_close_session(ctx->hdl);
    free(ctx);
    return NULL;
}

/* Init of the NVM storage manager. */
struct she_storage_context *she_storage_init(void)
{
    struct she_storage_context *nvm_ctx = NULL;
    int32_t error = -1;
    do {
        /* Prepare the context to be passed to the thread function. */
        nvm_ctx = malloc(sizeof(struct she_storage_context));
        if (nvm_ctx == NULL) {
            break;
        }
        (void)memset(nvm_ctx, 0 ,sizeof(struct she_storage_context));
        /* Open the SHE NVM session. */
        nvm_ctx->hdl = she_platform_open_storage_session();
        if (nvm_ctx->hdl == NULL) {
            break;
        }

        /* Open the SHE session on SECO side */
        if (she_open_session_command (nvm_ctx->hdl, &nvm_ctx->session_handle,
                SHE_STORAGE_DEFAULT_MU, SHE_STORAGE_DEFAULT_INTERRUPT_IDX, SHE_STORAGE_DEFAULT_TZ,
                SHE_STORAGE_DEFAULT_DID, SHE_STORAGE_DEFAULT_PRIORITY, SHE_STORAGE_DEFAULT_OPERATING_MODE) != ERC_NO_ERROR) {
            break;
        }

        /* Configures the shared buffer in secure memory used to commumicate blobs. */
        error = she_storage_setup_shared_buffer(nvm_ctx);
        if (error != 0) {
            break;
        }

        /* Try to import the NVM storage. */
        error = she_storage_import(nvm_ctx);

        // TODO: Handle errors. (currently Seco can generate himself a fake storage if we cannot provide it from here.)

        /* Start the background thread waiting for NVM commands from Seco. */
        error = she_platform_create_thread(nvm_ctx->hdl, &she_storage_thread, nvm_ctx);

    } while (false);

    /* error clean-up. */
    if ((error != 0) && (nvm_ctx != NULL)) {
        if (nvm_ctx->hdl != NULL) {
            if (nvm_ctx->session_handle != 0u) {
                /* Send the session close command to Seco. */
                (void)she_close_session_command (nvm_ctx->hdl, nvm_ctx->session_handle);
            }
            she_platform_close_session(nvm_ctx->hdl);
        }
        free(nvm_ctx);
        nvm_ctx = NULL;
    }
    return nvm_ctx;
}

int32_t she_storage_terminate(struct she_storage_context *nvm_ctx)
{
    int32_t err = 1;
    if (nvm_ctx->hdl != NULL) {
        if(nvm_ctx->session_handle != 0u) {
            (void)she_close_session_command (nvm_ctx->hdl, nvm_ctx->session_handle);
        }

        err = she_platform_cancel_thread(nvm_ctx->hdl);
        if (err == 0) {
            she_platform_close_session(nvm_ctx->hdl);
        }

    }
    if (err == 0) {
        free(nvm_ctx);
    }
    return err;
}
