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

#include "she_platform.h"
#include "messaging.h"
#include "she_msg.h"

/* Convert errors codes reported by Seco to SHE error codes. */
she_err_t she_seco_ind_to_she_err_t (uint32_t rsp_code)
{
    she_err_t err = ERC_GENERAL_ERROR;
    switch (GET_RATING_CODE(rsp_code)) {
    /* 1 to 1 mapping for all SHE specific error codes. */
    case SAB_SHE_SEQUENCE_ERROR_RATING :
        err = ERC_SEQUENCE_ERROR;
        break;
    case SAB_SHE_KEY_NOT_AVAILABLE_RATING :
        err = ERC_KEY_NOT_AVAILABLE;
        break;
    case  SAB_SHE_KEY_INVALID_RATING :
        err = ERC_KEY_INVALID;
        break;
    case SAB_SHE_KEY_EMPTY_RATING :
        err = ERC_KEY_EMPTY;
        break;
    case SAB_SHE_NO_SECURE_BOOT_RATING :
        err = ERC_NO_SECURE_BOOT;
        break;
    case SAB_SHE_KEY_WRITE_PROTECTED_RATING :
        err = ERC_KEY_WRITE_PROTECTED;
        break;
    case SAB_SHE_KEY_UPDATE_ERROR_RATING :
        err = ERC_KEY_UPDATE_ERROR;
        break;
    case SAB_SHE_RNG_SEED_RATING :
        err = ERC_RNG_SEED;
        break;
    case SAB_SHE_NO_DEBUGGING_RATING :
        err = ERC_NO_DEBUGGING;
        break;
    case SAB_SHE_BUSY_RATING :
        err = ERC_BUSY;
        break;
    case SAB_SHE_MEMORY_FAILURE_RATING :
        err = ERC_MEMORY_FAILURE;
        break;
    case SAB_SHE_GENERAL_ERROR_RATING :
        err = ERC_GENERAL_ERROR;
        break;
    /* All other SECO error codes. */
    default:
        err = ERC_GENERAL_ERROR;
        break;
    }
    return err;
}

/* Helper function to send a message and wait for the response. Return 0 on success.*/
int32_t she_send_msg_and_get_resp(struct she_platform_hdl *phdl, uint32_t *cmd, uint32_t cmd_len, uint32_t *rsp, uint32_t rsp_len)
{
    int32_t err = -1;
    int32_t len;

    do {
        /* Command and response need to be at least 1 word for the header. */
        if ((cmd_len < (uint32_t)sizeof(uint32_t)) || (rsp_len < (uint32_t)sizeof(uint32_t))) {
            break;
        }

        /* Send the command. */
        len = she_platform_send_mu_message(phdl, cmd, cmd_len);
        if (len != (int32_t)cmd_len) {
            break;
        }
        /* Read the response. */
        len = she_platform_read_mu_message(phdl, rsp, rsp_len);
        if (len != (int32_t)rsp_len) {
            break;
        }

        err = 0;
    } while (false);
    return err;
}


uint32_t she_compute_msg_crc(uint32_t *msg, uint32_t msg_len) {
    uint32_t crc;
    uint32_t i;
    uint32_t nb_words = msg_len / (uint32_t)sizeof(uint32_t);

    crc = 0u;
    for (i = 0u; i < nb_words; i++) {
        crc ^= *(msg + i);
    }
    return crc;
}

she_err_t she_close_session_command (struct she_platform_hdl *phdl, uint32_t session_handle) {
    struct sab_cmd_session_close_msg cmd;
    struct sab_cmd_session_close_rsp rsp;
    int32_t error;
    she_err_t err = ERC_GENERAL_ERROR;

    do {

        if (session_handle == 0u) {
            break;
        }

        she_fill_cmd_msg_hdr(&cmd.hdr, SAB_SESSION_CLOSE_REQ, (uint32_t)sizeof(struct sab_cmd_session_close_msg));
        cmd.sesssion_handle = session_handle;

        error =  she_send_msg_and_get_resp(phdl, (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_cmd_session_close_msg), (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_cmd_session_close_rsp));

        if (error != 0) {
            break;
        }

        if (GET_STATUS_CODE(rsp.rsp_code) != SAB_SUCCESS_STATUS) {
            err = she_seco_ind_to_she_err_t(rsp.rsp_code);
            break;
        }

            /* Success. */
    err = ERC_NO_ERROR;
    } while (false);

    return err;
}

she_err_t she_get_shared_buffer(struct she_platform_hdl *phdl, uint32_t session_handle, uint32_t *shared_buf_offset, uint32_t *shared_buf_size)
{
    struct sab_cmd_shared_buffer_msg cmd;
    struct sab_cmd_shared_buffer_rsp rsp;

    she_err_t err = ERC_GENERAL_ERROR;
    int32_t error = 1;
    do {

        if (session_handle == 0u) {
            break;
        }

        /* Send the keys store open command to Seco. */
        she_fill_cmd_msg_hdr(&cmd.hdr, SAB_SHARED_BUF_REQ, (uint32_t)sizeof(struct sab_cmd_shared_buffer_msg));

        cmd.sesssion_handle = session_handle;
        error = she_send_msg_and_get_resp(phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_cmd_shared_buffer_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_cmd_shared_buffer_rsp));

        if (error != 0) {
            break;
        }

        if (GET_STATUS_CODE(rsp.rsp_code) != SAB_SUCCESS_STATUS) {
            err = she_seco_ind_to_she_err_t(rsp.rsp_code);
            break;
        }

        *shared_buf_offset = rsp.shared_buf_offset;
        *shared_buf_size = rsp.shared_buf_size;
        /* Success. */
        err = ERC_NO_ERROR;
    } while(false);
    return err;
}

she_err_t she_open_session_command (struct she_platform_hdl *phdl, uint32_t *session_handle, uint8_t mu_id, uint8_t interrupt_idx, uint8_t tz, uint8_t did, uint8_t priority,uint8_t operating_mode) {
    struct sab_cmd_session_open_msg cmd;
    struct sab_cmd_session_open_rsp rsp;
    int32_t error;
    she_err_t err = ERC_GENERAL_ERROR;

    cmd.mu_id = mu_id;
    cmd.interrupt_idx = interrupt_idx;
    cmd.tz = tz;
    cmd.did = did;
    cmd.priority = priority;
    cmd.operating_mode = operating_mode;

    do {
        /* Send the session open command to Seco. */
        she_fill_cmd_msg_hdr((struct she_mu_hdr *)&cmd, SAB_SESSION_OPEN_REQ, (uint32_t)sizeof(struct sab_cmd_session_open_msg));


        error = she_send_msg_and_get_resp(phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_cmd_session_open_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_cmd_session_open_rsp));

        if (error != 0) {
            break;
        }

        if (GET_STATUS_CODE(rsp.rsp_code) != SAB_SUCCESS_STATUS) {
            err = she_seco_ind_to_she_err_t(rsp.rsp_code);
            break;
        }

        *session_handle = rsp.sesssion_handle;
        /* Success. */
        err = ERC_NO_ERROR;
    } while (false);

    return err;
}


uint32_t sab_open_key_store_command(struct she_platform_hdl *phdl, uint32_t session_handle, uint32_t *key_store_handle, uint32_t key_storage_identifier, uint32_t password, uint16_t max_updates, uint8_t flags)
{
    struct sab_cmd_key_store_open_msg cmd;
    struct sab_cmd_key_store_open_rsp rsp;

    uint32_t ret = SAB_FAILURE_STATUS;
    int32_t error = 1;
    do {
        /* Send the keys store open command to Seco. */
        she_fill_cmd_msg_hdr(&cmd.hdr, SAB_KEY_STORE_OPEN_REQ, (uint32_t)sizeof(struct sab_cmd_key_store_open_msg));

        cmd.sesssion_handle = session_handle;
        cmd.key_store_id = key_storage_identifier;
        cmd.password = password;
        cmd.flags = flags;
        cmd.max_updates = max_updates;
        cmd.crc = she_compute_msg_crc((uint32_t*)&cmd, (uint32_t)(sizeof(cmd) - sizeof(uint32_t)));

        error = she_send_msg_and_get_resp(phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_cmd_key_store_open_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_cmd_key_store_open_rsp));
        if (error != 0) {
            break;
        }

        ret = rsp.rsp_code;

        if (GET_STATUS_CODE(rsp.rsp_code) == SAB_SUCCESS_STATUS) {
            *key_store_handle = rsp.key_store_handle;
        }

    } while(false);
    return ret;
}

uint32_t sab_close_key_store(struct she_platform_hdl *phdl, uint32_t key_store_handle)
{
    struct sab_cmd_key_store_close_msg cmd;
    struct sab_cmd_key_store_close_rsp rsp;

    uint32_t ret = SAB_FAILURE_STATUS;
    int32_t error = 1;
    do {

        /* Send the keys store close command to Seco. */
        she_fill_cmd_msg_hdr(&cmd.hdr, SAB_KEY_STORE_CLOSE_REQ, (uint32_t)sizeof(struct sab_cmd_key_store_close_msg));
        cmd.key_store_handle = key_store_handle;

        error = she_send_msg_and_get_resp(phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_cmd_key_store_close_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_cmd_key_store_close_rsp));

        if (error != 0) {
            break;
        }

        ret = rsp.rsp_code;

    } while(false);
    return ret;
}


