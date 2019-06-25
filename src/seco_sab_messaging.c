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
#include "seco_sab_messaging.h"
#include "seco_sab_msg_def.h"
#include "seco_utils.h"

uint32_t sab_open_session_command (struct seco_os_abs_hdl *phdl, uint32_t *session_handle, uint8_t mu_id, uint8_t interrupt_idx, uint8_t tz, uint8_t did, uint8_t priority,uint8_t operating_mode) {
    struct sab_cmd_session_open_msg cmd;
    struct sab_cmd_session_open_rsp rsp;
    int32_t error;
    uint32_t ret = SAB_FAILURE_STATUS;

    do {
        /* Send the session open command to Seco. */
        seco_fill_cmd_msg_hdr((struct she_mu_hdr *)&cmd, SAB_SESSION_OPEN_REQ, (uint32_t)sizeof(struct sab_cmd_session_open_msg));
        cmd.mu_id = mu_id;
        cmd.interrupt_idx = interrupt_idx;
        cmd.tz = tz;
        cmd.did = did;
        cmd.priority = priority;
        cmd.operating_mode = operating_mode;

        error = seco_send_msg_and_get_resp(phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_cmd_session_open_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_cmd_session_open_rsp));
        if (error != 0) {
            break;
        }

        ret = rsp.rsp_code;
        *session_handle = rsp.session_handle;
    } while (false);

    return ret;
}

uint32_t sab_close_session_command (struct seco_os_abs_hdl *phdl, uint32_t session_handle) {
    struct sab_cmd_session_close_msg cmd;
    struct sab_cmd_session_close_rsp rsp;
    int32_t error;
    uint32_t ret = SAB_FAILURE_STATUS;

    do {
        seco_fill_cmd_msg_hdr(&cmd.hdr, SAB_SESSION_CLOSE_REQ, (uint32_t)sizeof(struct sab_cmd_session_close_msg));
        cmd.session_handle = session_handle;

        error =  seco_send_msg_and_get_resp(phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_cmd_session_close_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_cmd_session_close_rsp));
        if (error != 0) {
            break;
        }
        ret = rsp.rsp_code;
    } while (false);

    return ret;
}

uint32_t sab_get_shared_buffer(struct seco_os_abs_hdl *phdl, uint32_t session_handle)
{
    struct sab_cmd_shared_buffer_msg cmd;
    struct sab_cmd_shared_buffer_rsp rsp;
    int32_t error = 1;
    uint32_t ret = SAB_FAILURE_STATUS;

    do {
        /* Send the keys store open command to Seco. */
        seco_fill_cmd_msg_hdr(&cmd.hdr, SAB_SHARED_BUF_REQ, (uint32_t)sizeof(struct sab_cmd_shared_buffer_msg));

        cmd.session_handle = session_handle;
        error = seco_send_msg_and_get_resp(phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_cmd_shared_buffer_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_cmd_shared_buffer_rsp));
        if (error != 0) {
            break;
        }

        ret = rsp.rsp_code;
        if (GET_STATUS_CODE(ret) != SAB_SUCCESS_STATUS) {
            break;
        }

        /* Configure the shared buffer. */
        error = seco_os_abs_configure_shared_buf(phdl, rsp.shared_buf_offset, rsp.shared_buf_size);
        if (error != 0) {
            ret = SAB_FAILURE_STATUS;
            break;
        }
        ret = SAB_SUCCESS_STATUS;
    } while(false);
    return ret;
}

uint32_t sab_open_key_store_command(struct seco_os_abs_hdl *phdl, uint32_t session_handle, uint32_t *key_store_handle, uint32_t key_storage_identifier, uint32_t password, uint16_t max_updates, uint8_t flags)
{
    struct sab_cmd_key_store_open_msg cmd;
    struct sab_cmd_key_store_open_rsp rsp;

    uint32_t ret = SAB_FAILURE_STATUS;
    int32_t error = 1;
    do {
        /* Send the keys store open command to Seco. */
        seco_fill_cmd_msg_hdr(&cmd.hdr, SAB_KEY_STORE_OPEN_REQ, (uint32_t)sizeof(struct sab_cmd_key_store_open_msg));

        cmd.session_handle = session_handle;
        cmd.key_store_id = key_storage_identifier;
        cmd.password = password;
        cmd.flags = flags;
        cmd.max_updates = max_updates;
        cmd.crc = seco_compute_msg_crc((uint32_t*)&cmd, (uint32_t)(sizeof(cmd) - sizeof(uint32_t)));

        error = seco_send_msg_and_get_resp(phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_cmd_key_store_open_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_cmd_key_store_open_rsp));
        if (error != 0) {
            break;
        }

        ret = rsp.rsp_code;
        *key_store_handle = rsp.key_store_handle;
    } while(false);
    return ret;
}

uint32_t sab_close_key_store(struct seco_os_abs_hdl *phdl, uint32_t key_store_handle)
{
    struct sab_cmd_key_store_close_msg cmd;
    struct sab_cmd_key_store_close_rsp rsp;
    int32_t error = 1;
    uint32_t ret = SAB_FAILURE_STATUS;

    do {
        /* Send the keys store close command to Seco. */
        seco_fill_cmd_msg_hdr(&cmd.hdr, SAB_KEY_STORE_CLOSE_REQ, (uint32_t)sizeof(struct sab_cmd_key_store_close_msg));
        cmd.key_store_handle = key_store_handle;

        error = seco_send_msg_and_get_resp(phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_cmd_key_store_close_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_cmd_key_store_close_rsp));
        if (error != 0) {
            break;
        }

        ret = rsp.rsp_code;

    } while(false);
    return ret;
}

uint32_t sab_open_cipher(struct seco_os_abs_hdl *phdl, uint32_t key_store_handle, uint32_t *cipher_handle, uint8_t flags)
{
    struct sab_cmd_cipher_open_msg cmd;
    struct sab_cmd_cipher_open_rsp rsp;
    int32_t error = 1;
    uint32_t ret = SAB_FAILURE_STATUS;

    do {
        /* Send the cipher open command to Seco. */
        seco_fill_cmd_msg_hdr(&cmd.hdr, SAB_CIPHER_OPEN_REQ, (uint32_t)sizeof(struct sab_cmd_cipher_open_msg));
        cmd.input_address_ext = 0;
        cmd.output_address_ext = 0;
        cmd.flags = flags;
        cmd.key_store_handle = key_store_handle;
        cmd.crc = seco_compute_msg_crc((uint32_t*)&cmd, (uint32_t)(sizeof(cmd) - sizeof(uint32_t)));

        error = seco_send_msg_and_get_resp(phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_cmd_cipher_open_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_cmd_cipher_open_rsp));
        if (error != 0) {
            break;
        }

        ret = rsp.rsp_code;
        *cipher_handle = rsp.cipher_handle;
    } while(false);
    return ret;
}

uint32_t sab_close_cipher(struct seco_os_abs_hdl *phdl, uint32_t cipher_handle)
{
    struct sab_cmd_cipher_close_msg cmd;
    struct sab_cmd_cipher_close_rsp rsp;
    int32_t error = 1;
    uint32_t ret = SAB_FAILURE_STATUS;

    do {
        /* Send the cipher store close command to Seco. */
        seco_fill_cmd_msg_hdr(&cmd.hdr, SAB_CIPHER_CLOSE_REQ, (uint32_t)sizeof(struct sab_cmd_cipher_close_msg));
        cmd.cipher_handle = cipher_handle;
        error = seco_send_msg_and_get_resp(phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_cmd_cipher_close_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_cmd_cipher_close_rsp));

        if (error != 0) {
            break;
        }

        ret = rsp.rsp_code;
    } while(false);
    return ret;
}

uint32_t sab_open_rng(struct seco_os_abs_hdl *phdl, uint32_t session_handle, uint32_t *rng_handle, uint8_t flags)
{
    struct sab_cmd_rng_open_msg cmd;
    struct sab_cmd_rng_open_rsp rsp;
    int32_t error = 1;
    uint32_t ret = SAB_FAILURE_STATUS;

    do {
        /* Send the keys store open command to Seco. */
        seco_fill_cmd_msg_hdr(&cmd.hdr, SAB_RNG_OPEN_REQ, (uint32_t)sizeof(struct sab_cmd_rng_open_msg));
        cmd.session_handle = session_handle;
        cmd.input_address_ext = 0u;
        cmd.output_address_ext = 0u;
        cmd.flags = flags;
        cmd.crc = seco_compute_msg_crc((uint32_t*)&cmd, (uint32_t)(sizeof(cmd) - sizeof(uint32_t)));

        /* Send the message to Seco. */
        error = seco_send_msg_and_get_resp(phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_cmd_rng_open_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_cmd_rng_open_rsp));
        if (error != 0) {
            break;
        }

        ret = rsp.rsp_code;
        *rng_handle = rsp.rng_handle;
    } while(false);

    return ret;
}

uint32_t sab_close_rng(struct seco_os_abs_hdl *phdl, uint32_t rng_handle)
{
    struct sab_cmd_rng_close_msg cmd;
    struct sab_cmd_rng_close_rsp rsp;
    int32_t error = 1;
    uint32_t ret = SAB_FAILURE_STATUS;

    do {
        /* Send the keys store open command to Seco. */
        seco_fill_cmd_msg_hdr(&cmd.hdr, SAB_RNG_CLOSE_REQ, (uint32_t)sizeof(struct sab_cmd_rng_close_msg));
        cmd.rng_handle = rng_handle;
        error = seco_send_msg_and_get_resp(phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_cmd_rng_close_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_cmd_rng_close_rsp));

        if (error != 0) {
            break;
        }

        ret = rsp.rsp_code;
    } while(false);
    return ret;
}

uint32_t sab_open_storage_command(struct seco_os_abs_hdl *phdl, uint32_t session_handle, uint32_t *storage_handle, uint8_t flags)
{
    struct sab_cmd_storage_open_msg cmd;
    struct sab_cmd_storage_open_rsp rsp;
    int32_t error = 1;
    uint32_t ret = SAB_FAILURE_STATUS;

    do {
        /* Send the Storage open command to Seco. */
        seco_fill_cmd_msg_hdr(&cmd.hdr, SAB_STORAGE_OPEN_REQ, (uint32_t)sizeof(struct sab_cmd_storage_open_msg));
        cmd.session_handle = session_handle;
        cmd.input_address_ext = 0u;
        cmd.output_address_ext = 0u;
        cmd.flags = flags;
        cmd.crc = seco_compute_msg_crc((uint32_t*)&cmd, (uint32_t)(sizeof(cmd) - sizeof(uint32_t)));

        /* Send the message to Seco. */
        error = seco_send_msg_and_get_resp(phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_cmd_storage_open_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_cmd_storage_open_rsp));
        if (error != 0) {
            break;
        }

        ret = rsp.rsp_code;
        *storage_handle = rsp.storage_handle;
    } while(false);

    return ret;
}

uint32_t sab_close_storage_command(struct seco_os_abs_hdl *phdl, uint32_t storage_handle)
{
    struct sab_cmd_storage_close_msg cmd;
    struct sab_cmd_storage_close_rsp rsp;
    int32_t error = 1;
    uint32_t ret = SAB_FAILURE_STATUS;

    do {
        /* Send the Storage close command to Seco. */
        seco_fill_cmd_msg_hdr(&cmd.hdr, SAB_STORAGE_CLOSE_REQ, (uint32_t)sizeof(struct sab_cmd_storage_close_msg));
        cmd.storage_handle = storage_handle;
        error = seco_send_msg_and_get_resp(phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_cmd_storage_close_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_cmd_storage_close_rsp));

        if (error != 0) {
            break;
        }

        ret = rsp.rsp_code;
    } while(false);
    return ret;
}

uint32_t sab_get_info(struct seco_os_abs_hdl *phdl, uint32_t session_handle, uint32_t *user_sab_id, uint8_t *chip_unique_id, uint16_t *chip_monotonic_counter, uint16_t *chip_life_cycle, uint32_t *version, uint32_t *version_ext, uint8_t *fips_mode)
{
    struct sab_cmd_get_info_msg cmd;
    struct sab_cmd_get_info_rsp rsp;
    int32_t error = 1;
    uint32_t ret = SAB_FAILURE_STATUS;

    do {

        /* Send the keys store open command to Seco. */
        seco_fill_cmd_msg_hdr(&cmd.hdr, SAB_GET_INFO_REQ, (uint32_t)sizeof(struct sab_cmd_get_info_msg));
        cmd.session_handle = session_handle;

        /* Send the message to Seco. */
        error = seco_send_msg_and_get_resp(phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_cmd_get_info_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_cmd_get_info_rsp));

        if ((error != 0)
            || (rsp.crc != seco_compute_msg_crc((uint32_t*)&rsp, (uint32_t)(sizeof(rsp) - sizeof(uint32_t))))) {
            break;
        }

        ret = rsp.rsp_code;
        *user_sab_id = rsp.user_sab_id;
        seco_os_abs_memcpy(chip_unique_id, (uint8_t *)&rsp.uid_lower, sizeof(rsp.uid_lower));
        seco_os_abs_memcpy(chip_unique_id + sizeof(rsp.uid_lower), (uint8_t *)&rsp.uid_upper, sizeof(rsp.uid_upper));
        *chip_monotonic_counter = rsp.monotonic_counter;
        *chip_life_cycle = rsp.lifecycle;
        *version = rsp.version;
        *version_ext = rsp.version_ext;
        *fips_mode = rsp.fips_mode;
    } while(false);

    return ret;
}
