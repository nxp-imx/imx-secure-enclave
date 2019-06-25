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

#include "seco_os_abs.h"
#include "seco_sab_msg_def.h"
#include "seco_sab_messaging.h"
#include "seco_utils.h"
#include "seco_nvm.h"

struct seco_nvm_ctx {
    struct seco_os_abs_hdl *phdl;
    uint32_t session_handle;
    uint32_t storage_handle;
    uint32_t blob_size;
};

struct seco_nvm_header_s {
    uint32_t size;
    uint32_t crc;
};

/* Storage import processing. Return 0 on success.  */
static uint32_t seco_nvm_storage_import(struct seco_nvm_ctx *nvm_ctx, uint8_t *data, uint32_t len)
{
    struct sab_cmd_key_store_import_msg msg;
    struct sab_cmd_key_store_import_rsp rsp;
    uint64_t seco_addr;
    struct seco_nvm_header_s *blob_hdr;
    uint32_t ret = SAB_FAILURE_STATUS;
    int32_t error;

    do {
        if (nvm_ctx->storage_handle == 0u) {
            break;
        }
   
        blob_hdr = (struct seco_nvm_header_s *)data;
      
        /* Sanity check on the provided data. */
        if (blob_hdr->size + (uint32_t)sizeof(struct seco_nvm_header_s) != len) {
            break;
        }
     
        if (seco_os_abs_crc(data + sizeof(struct seco_nvm_header_s), blob_hdr->size) != blob_hdr->crc) {
            break;
        }
      
        seco_addr = seco_os_abs_data_buf(nvm_ctx->phdl, data + sizeof(struct seco_nvm_header_s), blob_hdr->size, DATA_BUF_IS_INPUT);
  
        /* Prepare command message. */
        seco_fill_cmd_msg_hdr(&msg.hdr, SAB_STORAGE_IMPORT_REQ, (uint32_t)sizeof(struct sab_cmd_key_store_import_msg));
        msg.storage_handle = nvm_ctx->storage_handle;
        msg.key_store_address = (uint32_t)(seco_addr & 0xFFFFFFFFu);
        msg.key_store_size = blob_hdr->size;
     
        error = seco_send_msg_and_get_resp(nvm_ctx->phdl,
                    (uint32_t *)&msg, (uint32_t)sizeof(struct sab_cmd_key_store_import_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_cmd_key_store_import_rsp));
        if (error != 0) {        
            break;
        }
        /* report error status from Seco. */
        ret = rsp.rsp_code;
    } while (false);     
    return ret;
}

static void seco_nvm_close_session(struct seco_nvm_ctx *nvm_ctx)
{
    if (nvm_ctx != NULL) {
        if (nvm_ctx->phdl != NULL) {
            if (nvm_ctx->storage_handle != 0u) {
                (void)sab_close_storage_command (nvm_ctx->phdl, nvm_ctx->storage_handle);
                nvm_ctx->storage_handle = 0u;
            }          
            if (nvm_ctx->session_handle != 0u) {
                (void)sab_close_session_command (nvm_ctx->phdl, nvm_ctx->session_handle);
                nvm_ctx->session_handle = 0u;
            }
            seco_os_abs_close_session(nvm_ctx->phdl);
            nvm_ctx->phdl = NULL;
        }
        seco_os_abs_free(nvm_ctx);
    }
}

static struct seco_nvm_ctx *seco_nvm_open_session(uint8_t flags)
{
    struct seco_nvm_ctx *nvm_ctx = NULL;
    uint32_t err = SAB_FAILURE_STATUS;
    struct seco_mu_params mu_params;

    do {
        /* allocate the handle. */
        nvm_ctx = (struct seco_nvm_ctx *)seco_os_abs_malloc((uint32_t)sizeof(struct seco_nvm_ctx));
        if (nvm_ctx == NULL) {
            break;
        }

        seco_os_abs_memset((uint8_t *)nvm_ctx, 0u, (uint32_t)sizeof(struct seco_nvm_ctx));

        /* Open the Storage session on the MU*/
        if ((flags & NVM_FLAGS_SHE) != 0u) {
            nvm_ctx->phdl = seco_os_abs_open_mu_channel(MU_CHANNEL_SHE_NVM, &mu_params);
        } else if ((flags & NVM_FLAGS_HSM) != 0u) {
            nvm_ctx->phdl = seco_os_abs_open_mu_channel(MU_CHANNEL_HSM_NVM, &mu_params);
        } else {
            nvm_ctx->phdl = NULL;
        }
        if (nvm_ctx->phdl == NULL) {
            break;
        }

        /* Open the SHE session on SECO side */
        err = sab_open_session_command(nvm_ctx->phdl,
                                       &nvm_ctx->session_handle,
                                       mu_params.mu_id,
                                       mu_params.interrupt_idx,
                                       mu_params.tz,
                                       mu_params.did,
                                       mu_params.priority,
                                       mu_params.operating_mode);
        if (err != SAB_SUCCESS_STATUS) {
            nvm_ctx->session_handle = 0u;
            break;
        }

        /* Get a SECURE RAM partition to be used as shared buffer */
        err = sab_get_shared_buffer(nvm_ctx->phdl, nvm_ctx->session_handle);
        if (err != SAB_SUCCESS_STATUS) {
            break;
        }

        /* Open the SHE NVM STORAGE session on SECO side */
        err = sab_open_storage_command(nvm_ctx->phdl,
                                        nvm_ctx->session_handle,
                                        &nvm_ctx->storage_handle,
                                        flags);
        if (err != SAB_SUCCESS_STATUS) {
            nvm_ctx->storage_handle = 0u;
            break;
        }
    } while (false);

    /* Clean-up in case of error. */
    if ((err != SAB_SUCCESS_STATUS) && (nvm_ctx != NULL)) {
        seco_nvm_close_session(nvm_ctx);
        nvm_ctx = NULL;
    }
    return nvm_ctx;
}

static uint32_t seco_nvm_get_data_len(struct seco_nvm_ctx *nvm_ctx)
{
    struct sab_cmd_key_store_export_start_msg msg;
    uint32_t ret = 0u;
    int32_t len;

    do {
        if (nvm_ctx->storage_handle == 0u) {
            break;
        }
        /* Wait for the message initializing the transaction. */
        len = seco_os_abs_read_mu_message(nvm_ctx->phdl, (uint32_t *)&msg, (uint32_t)sizeof(struct sab_cmd_key_store_export_start_msg));
        if ((msg.hdr.command != SAB_STORAGE_START_REQ) 
            || (len != (int32_t)sizeof(struct sab_cmd_key_store_export_start_msg))) {
            break;
        }
        /* success. */
        nvm_ctx->blob_size = msg.key_store_size;
        ret = msg.key_store_size + (uint32_t)sizeof(struct seco_nvm_header_s);
    } while (false);

    return ret;

}

static uint32_t seco_nvm_get_data(struct seco_nvm_ctx *nvm_ctx, uint8_t *dst)
{
    struct sab_cmd_key_store_export_start_rsp resp;
    struct sab_cmd_key_store_export_finish_msg msg;
    uint64_t seco_addr;
    uint32_t ret = SAB_FAILURE_STATUS;
    int32_t len;
    struct seco_nvm_header_s *blob_hdr;

    do {
        if (nvm_ctx->storage_handle == 0u) {
            break;
        }
        /* Build the response indicating the destination address to SECO. */
        seco_fill_rsp_msg_hdr(&resp.hdr, SAB_STORAGE_START_REQ, (uint32_t)sizeof(struct sab_cmd_key_store_export_start_rsp));

        if (dst != NULL) {
            seco_addr = seco_os_abs_data_buf(nvm_ctx->phdl,
                                            dst + (uint32_t)sizeof(struct seco_nvm_header_s),
                                            nvm_ctx->blob_size,
                                            0u);
            resp.key_store_export_address = (uint32_t)(seco_addr & 0xFFFFFFFFu);
            resp.rsp_code = SAB_SUCCESS_STATUS;
        } else {
            resp.key_store_export_address = 0;
            resp.rsp_code = SAB_FAILURE_STATUS;
        }

        resp.storage_handle = nvm_ctx->storage_handle;

        len = seco_os_abs_send_mu_message(nvm_ctx->phdl, (uint32_t *)&resp, (uint32_t)sizeof(struct sab_cmd_key_store_export_start_rsp));
        if (len != (int32_t)sizeof(struct sab_cmd_key_store_export_start_rsp)) {
            break;
        }

        if (dst != NULL) {
            /* Wait for the message from SECO indicating that the data are available at the specified destination. */
            len = seco_os_abs_read_mu_message(nvm_ctx->phdl, (uint32_t *)&msg, (uint32_t)sizeof(struct sab_cmd_key_store_export_finish_msg));
            if ((msg.hdr.command != SAB_STORAGE_FINISH_REQ) 
                || (len != (int32_t)sizeof(struct sab_cmd_key_store_export_finish_msg))) {
                break;
            }

            if (msg.export_status != SAB_EXPORT_STATUS_SUCCESS) {
                break;
            }

            /* fill header for sanity check when re-loading */
            blob_hdr = (struct seco_nvm_header_s *)dst;
            blob_hdr->size = nvm_ctx->blob_size;
            blob_hdr->crc = seco_os_abs_crc(dst + sizeof(struct seco_nvm_header_s),  nvm_ctx->blob_size);
            nvm_ctx->blob_size = 0u;
            /* success. */
        }

        ret = SAB_SUCCESS_STATUS;
    } while (false);

    return ret;
}


static uint32_t seco_nvm_write_status(struct seco_nvm_ctx *nvm_ctx, uint32_t error)
{
    struct sab_cmd_key_store_export_finish_rsp resp;
    uint32_t ret = SAB_FAILURE_STATUS;
    int32_t len;

    do {
        if (nvm_ctx->storage_handle == 0u) {
            break;
        }
        seco_fill_rsp_msg_hdr(&resp.hdr, SAB_STORAGE_FINISH_REQ, (uint32_t)sizeof(struct sab_cmd_key_store_export_finish_rsp));
        if (error == 0u) {
            resp.rsp_code = SAB_SUCCESS_STATUS;
        } else {
            resp.rsp_code = SAB_FAILURE_STATUS;
        }
        resp.storage_handle = nvm_ctx->storage_handle;
        len = seco_os_abs_send_mu_message(nvm_ctx->phdl, (uint32_t *)&resp, (uint32_t)sizeof(struct sab_cmd_key_store_export_finish_rsp));
        if (len != (int32_t)sizeof(struct sab_cmd_key_store_export_finish_rsp)) {
            break;
        }
        /* success. */
        ret = SAB_SUCCESS_STATUS;
    } while (false);

    return ret;
}

void seco_nvm_manager(uint8_t flags, uint32_t *status)
{
    struct seco_nvm_ctx *nvm_ctx;
    uint32_t len = 0u;
    uint8_t *data = NULL;
    struct seco_nvm_header_s nvm_hdr;

    if (status != NULL) {
        *status = NVM_STATUS_STARTING;
    }

    do {
        nvm_ctx = seco_nvm_open_session(flags);
        if (nvm_ctx == NULL) {
            break;
        }

        /*
         * Try to read the storage header which length is known.
         * Then if successful extract the full length and read the whole storage into an allocated buffer.
         */
        if (seco_os_abs_storage_read(nvm_ctx->phdl, (uint8_t *)&nvm_hdr, (uint32_t)sizeof(nvm_hdr)) == (int32_t)sizeof(nvm_hdr)) {
            len = (uint32_t)(nvm_hdr.size + sizeof(nvm_hdr));
            data = seco_os_abs_malloc(len);
            if (data != NULL) {
                if (seco_os_abs_storage_read(nvm_ctx->phdl, data, len) == (int32_t)len) {
                    /* In case of error then start anyway the storage manager process so SECO can create
                     * and export a storage.
                     */
                    (void)seco_nvm_storage_import(nvm_ctx, data, len);
                }
                seco_os_abs_free(data);
                data = NULL;
                len = 0u;
            }
        }

        if (status != NULL) {
            *status = NVM_STATUS_RUNNING;
        }

        /* Infinite loop waiting for SECO commands. */
        while (true)
        {
            len = seco_nvm_get_data_len(nvm_ctx);
            if ((len == 0u) || (len > 16u*1024u)) {
                /* Fixing arbitrary maximum storage size to 16k for sanity checks.*/
                break;
            }

            data = seco_os_abs_malloc(len);
            if (data == NULL) {
                break;
            }

            if (seco_nvm_get_data(nvm_ctx, data) != SAB_SUCCESS_STATUS) {
                break;
            }

            if (seco_os_abs_storage_write(nvm_ctx->phdl, data, len) == (int32_t)len) {
                /* Success. */
                (void)seco_nvm_write_status(nvm_ctx, 0u);
            } else {
                /* Notify SECO of an error during write to NVM. */
                (void)seco_nvm_write_status(nvm_ctx, 1u);
            }

            seco_os_abs_free(data);
            data = NULL;
        }
    } while (false);

    if (status != NULL) {
        *status = NVM_STATUS_STOPPED;
    }

    if (data != NULL) {
        seco_os_abs_free(data);
        data = NULL;
    }

    if (nvm_ctx != NULL) {
        seco_nvm_close_session(nvm_ctx);
    }
}
