/*
 * Copyright 2019-2022 NXP
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

#include "sab_messaging.h"
#include "sab_msg_def.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t sab_get_shared_buffer(struct plat_os_abs_hdl *phdl, uint32_t session_handle, uint32_t mu_type)
{
    struct sab_cmd_shared_buffer_msg cmd;
    struct sab_cmd_shared_buffer_rsp rsp;
    int32_t error = 1;
    uint32_t ret = SAB_FAILURE_STATUS;

    do {
        /* Send the keys store open command to Platform. */
        plat_fill_cmd_msg_hdr(&cmd.hdr, SAB_SHARED_BUF_REQ, (uint32_t)sizeof(struct sab_cmd_shared_buffer_msg), mu_type);

        cmd.session_handle = session_handle;
        error = plat_send_msg_and_get_resp(phdl,
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
        error = plat_os_abs_configure_shared_buf(phdl, rsp.shared_buf_offset, rsp.shared_buf_size);
        if (error != 0) {
            ret = SAB_FAILURE_STATUS;
            break;
        }
        ret = SAB_SUCCESS_STATUS;
    } while(false);
    return ret;
}

uint32_t sab_open_key_store_command(struct plat_os_abs_hdl *phdl, uint32_t session_handle, uint32_t *key_store_handle, uint32_t mu_type, uint32_t key_storage_identifier, uint32_t password, uint16_t max_updates, uint8_t flags, uint8_t min_mac_length)
{
    struct sab_cmd_key_store_open_msg cmd;
    struct sab_cmd_key_store_open_rsp rsp;

    uint32_t ret = SAB_FAILURE_STATUS;
    int32_t error = 1;
    do {
        /* Send the keys store open command to Platform. */
        plat_fill_cmd_msg_hdr(&cmd.hdr, SAB_KEY_STORE_OPEN_REQ, (uint32_t)sizeof(struct sab_cmd_key_store_open_msg), mu_type);

        cmd.session_handle = session_handle;
        cmd.key_store_id = key_storage_identifier;
        cmd.password = password;
        cmd.flags = flags;
        cmd.max_updates = max_updates;
        cmd.min_mac_length = min_mac_length;
        cmd.crc = plat_compute_msg_crc((uint32_t*)&cmd, (uint32_t)(sizeof(cmd) - sizeof(uint32_t)));

        error = plat_send_msg_and_get_resp(phdl,
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

uint32_t sab_close_key_store(struct plat_os_abs_hdl *phdl, uint32_t key_store_handle, uint32_t mu_type)
{
    struct sab_cmd_key_store_close_msg cmd;
    struct sab_cmd_key_store_close_rsp rsp;
    int32_t error = 1;
    uint32_t ret = SAB_FAILURE_STATUS;

    do {
        /* Send the keys store close command to Platform. */
        plat_fill_cmd_msg_hdr(&cmd.hdr, SAB_KEY_STORE_CLOSE_REQ, (uint32_t)sizeof(struct sab_cmd_key_store_close_msg), mu_type);
        cmd.key_store_handle = key_store_handle;

        error = plat_send_msg_and_get_resp(phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_cmd_key_store_close_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_cmd_key_store_close_rsp));
        if (error != 0) {
            break;
        }

        ret = rsp.rsp_code;

    } while(false);
    return ret;
}

uint32_t sab_open_rng(struct plat_os_abs_hdl *phdl, uint32_t session_handle, uint32_t *rng_handle, uint32_t mu_type, uint8_t flags)
{
    struct sab_cmd_rng_open_msg cmd;
    struct sab_cmd_rng_open_rsp rsp;
    int32_t error = 1;
    uint32_t ret = SAB_FAILURE_STATUS;

    do {
        /* Send the keys store open command to Platform. */
        plat_fill_cmd_msg_hdr(&cmd.hdr, SAB_RNG_OPEN_REQ, (uint32_t)sizeof(struct sab_cmd_rng_open_msg), mu_type);
        cmd.session_handle = session_handle;
        cmd.input_address_ext = 0u;
        cmd.output_address_ext = 0u;
        cmd.flags = flags;
        cmd.crc = plat_compute_msg_crc((uint32_t*)&cmd, (uint32_t)(sizeof(cmd) - sizeof(uint32_t)));

        /* Send the message to Platform. */
        error = plat_send_msg_and_get_resp(phdl,
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

uint32_t sab_close_rng(struct plat_os_abs_hdl *phdl, uint32_t rng_handle, uint32_t mu_type)
{
    struct sab_cmd_rng_close_msg cmd;
    struct sab_cmd_rng_close_rsp rsp;
    int32_t error = 1;
    uint32_t ret = SAB_FAILURE_STATUS;

    do {
        /* Send the keys store open command to Platform. */
        plat_fill_cmd_msg_hdr(&cmd.hdr, SAB_RNG_CLOSE_REQ, (uint32_t)sizeof(struct sab_cmd_rng_close_msg), mu_type);
        cmd.rng_handle = rng_handle;
        error = plat_send_msg_and_get_resp(phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_cmd_rng_close_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_cmd_rng_close_rsp));

        if (error != 0) {
            break;
        }

        ret = rsp.rsp_code;
    } while(false);
    return ret;
}

uint32_t sab_open_storage_command(struct plat_os_abs_hdl *phdl, uint32_t session_handle, uint32_t *storage_handle, uint32_t mu_type, uint8_t flags)
{
    struct sab_cmd_storage_open_msg cmd = {0};
    struct sab_cmd_storage_open_rsp rsp = {0};
    int32_t error = 1;
    uint32_t ret = SAB_FAILURE_STATUS;

    do {
        /* Send the Storage open command to Platform. */
        plat_fill_cmd_msg_hdr(&cmd.hdr, SAB_STORAGE_OPEN_REQ, (uint32_t)sizeof(struct sab_cmd_storage_open_msg), mu_type);
        cmd.session_handle = session_handle;
        cmd.input_address_ext = 0u;
        cmd.output_address_ext = 0u;
        cmd.flags = flags;
        cmd.crc = plat_compute_msg_crc((uint32_t*)&cmd, (uint32_t)(sizeof(cmd) - sizeof(uint32_t)));

        /* Send the message to Platform. */
        error = plat_send_msg_and_get_resp(phdl,
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

uint32_t sab_close_storage_command(struct plat_os_abs_hdl *phdl, uint32_t storage_handle, uint32_t mu_type)
{
    struct sab_cmd_storage_close_msg cmd;
    struct sab_cmd_storage_close_rsp rsp;
    int32_t error = 1;
    uint32_t ret = SAB_FAILURE_STATUS;

    do {
        /* Send the Storage close command to Platform. */
        plat_fill_cmd_msg_hdr(&cmd.hdr, SAB_STORAGE_CLOSE_REQ, (uint32_t)sizeof(struct sab_cmd_storage_close_msg), mu_type);
        cmd.storage_handle = storage_handle;
        error = plat_send_msg_and_get_resp(phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_cmd_storage_close_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_cmd_storage_close_rsp));

        if (error != 0) {
            break;
        }

        ret = rsp.rsp_code;
    } while(false);
    return ret;
}

uint32_t sab_get_info(struct plat_os_abs_hdl *phdl, uint32_t session_handle, uint32_t mu_type, uint32_t *user_sab_id, uint8_t *chip_unique_id, uint16_t *chip_monotonic_counter, uint16_t *chip_life_cycle, uint32_t *version, uint32_t *version_ext, uint8_t *fips_mode)
{
    struct sab_cmd_get_info_msg cmd;
    struct sab_cmd_get_info_rsp rsp;
    int32_t error = 1;
    uint32_t ret = SAB_FAILURE_STATUS;

    do {

        /* Send the keys store open command to Platform. */
        plat_fill_cmd_msg_hdr(&cmd.hdr, SAB_GET_INFO_REQ, (uint32_t)sizeof(struct sab_cmd_get_info_msg), mu_type);
        cmd.session_handle = session_handle;

        /* Send the message to Platform. */
        error = plat_send_msg_and_get_resp(phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_cmd_get_info_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_cmd_get_info_rsp));

        if (error != 0) {
            /*|| (rsp.crc != plat_compute_msg_crc((uint32_t*)&rsp, (uint32_t)(sizeof(rsp) - sizeof(uint32_t)))))*/
            break;
        }

        ret = rsp.rsp_code;
        *user_sab_id = rsp.user_sab_id;
        plat_os_abs_memcpy(chip_unique_id, (uint8_t *)&rsp.uid_lower, (uint32_t)sizeof(rsp.uid_lower));
        plat_os_abs_memcpy(chip_unique_id + sizeof(rsp.uid_lower), (uint8_t *)&rsp.uid_upper, (uint32_t)sizeof(rsp.uid_upper));
        *chip_monotonic_counter = rsp.monotonic_counter;
        *chip_life_cycle = rsp.lifecycle;
        *version = rsp.version;
        *version_ext = rsp.version_ext;
        *fips_mode = rsp.fips_mode;
    } while(false);

    return ret;
}

uint32_t sab_open_sm2_eces(struct plat_os_abs_hdl *phdl, uint32_t key_store_handle, uint32_t *sm2_eces_handle, uint32_t mu_type, uint8_t flags)
{
    struct sab_cmd_sm2_eces_dec_open_msg cmd;
    struct sab_cmd_sm2_eces_dec_open_rsp rsp;
    int32_t error = 1;
    uint32_t ret = SAB_FAILURE_STATUS;

    do {
        plat_fill_cmd_msg_hdr(&cmd.hdr, SAB_SM2_ECES_DEC_OPEN_REQ, (uint32_t)sizeof(struct sab_cmd_sm2_eces_dec_open_msg), mu_type);
        cmd.input_address_ext = 0;
        cmd.output_address_ext = 0;
        cmd.flags = flags;
        cmd.key_store_handle = key_store_handle;
        cmd.rsv[0] = 0u;
		cmd.rsv[1] = 0u;
		cmd.rsv[2] = 0u;
        cmd.crc = 0u;
        cmd.crc = plat_compute_msg_crc((uint32_t*)&cmd, (uint32_t)(sizeof(cmd) - sizeof(uint32_t)));

        error = plat_send_msg_and_get_resp(phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_cmd_sm2_eces_dec_open_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_cmd_sm2_eces_dec_open_rsp));
        if (error != 0) {
            break;
        }

        ret = rsp.rsp_code;
        *sm2_eces_handle = rsp.sm2_eces_handle;
    } while(false);
    return ret;
}

uint32_t sab_close_sm2_eces(struct plat_os_abs_hdl *phdl, uint32_t sm2_eces_handle, uint32_t mu_type)
{
    struct sab_cmd_sm2_eces_dec_close_msg cmd;
    struct sab_cmd_sm2_eces_dec_close_rsp rsp;
    int32_t error = 1;
    uint32_t ret = SAB_FAILURE_STATUS;

    do {
        plat_fill_cmd_msg_hdr(&cmd.hdr, SAB_SM2_ECES_DEC_CLOSE_REQ, (uint32_t)sizeof(struct sab_cmd_sm2_eces_dec_close_msg), mu_type);
        cmd.sm2_eces_handle = sm2_eces_handle;
        error = plat_send_msg_and_get_resp(phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_cmd_sm2_eces_dec_close_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_cmd_sm2_eces_dec_close_rsp));

        if (error != 0) {
            break;
        }

        ret = rsp.rsp_code;
    } while(false);
    return ret;
}
