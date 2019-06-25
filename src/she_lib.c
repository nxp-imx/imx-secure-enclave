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
#include "she_api.h"

struct she_hdl_s {
    struct seco_os_abs_hdl *phdl;
    uint32_t session_handle;
    uint32_t key_store_handle;
    uint32_t cipher_handle;
    uint32_t rng_handle;
    uint32_t utils_handle;
    uint32_t cancel;
    uint32_t last_rating;
};


/* Convert errors codes reported by Seco to SHE error codes. */
static she_err_t she_seco_ind_to_she_err_t (uint32_t rsp_code)
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



static she_err_t she_open_utils(struct she_hdl_s *hdl)
{
    struct sab_cmd_she_utils_open_msg cmd;
    struct sab_cmd_she_utils_open_rsp rsp;
    she_err_t ret = ERC_GENERAL_ERROR;
    int32_t error = 1;
    do {

        if (hdl->utils_handle != 0u) {
            break;
        }
        /* Send the keys store open command to Seco. */
        seco_fill_cmd_msg_hdr(&cmd.hdr, SAB_SHE_UTILS_OPEN, (uint32_t)sizeof(struct sab_cmd_she_utils_open_msg));
        cmd.input_address_ext = 0;
        cmd.output_address_ext = 0;
        cmd.key_store_handle = hdl->key_store_handle;

        error = seco_send_msg_and_get_resp(hdl->phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_cmd_she_utils_open_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_cmd_she_utils_open_rsp));

        if (error != 0) {
            break;
        }

        hdl->last_rating = rsp.rsp_code;
        if (GET_STATUS_CODE(rsp.rsp_code) != SAB_SUCCESS_STATUS) {
            ret = she_seco_ind_to_she_err_t(rsp.rsp_code);
            break;
        }

        hdl->utils_handle = rsp.utils_handle;
        /* Success. */
        ret = ERC_NO_ERROR;
    } while(false);
    return ret;
}

static she_err_t she_close_utils(struct she_hdl_s *hdl)
{
    struct sab_cmd_she_utils_close_msg cmd;
    struct sab_cmd_she_utils_close_rsp rsp;
    she_err_t ret = ERC_GENERAL_ERROR;
    int32_t error = 1;
    do {
        if (hdl->utils_handle == 0u){
            break;
        }
        /* Send the keys store open command to Seco. */
        seco_fill_cmd_msg_hdr(&cmd.hdr, SAB_SHE_UTILS_CLOSE, (uint32_t)sizeof(struct sab_cmd_she_utils_close_msg));
        cmd.utils_handle = hdl->utils_handle;
        error = seco_send_msg_and_get_resp(hdl->phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_cmd_she_utils_close_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_cmd_she_utils_close_rsp));

        if (error != 0) {
            break;
        }

        hdl->last_rating = rsp.rsp_code;
        if (GET_STATUS_CODE(rsp.rsp_code) != SAB_SUCCESS_STATUS) {
            ret = she_seco_ind_to_she_err_t(rsp.rsp_code);
            break;
        }

        hdl->cipher_handle = 0u;
        /* Success. */
        ret = ERC_NO_ERROR;
    } while(false);
    return ret;
}

/* Close a previously opened SHE session. */
void she_close_session(struct she_hdl_s *hdl)
{
    if (hdl != NULL) {
        if (hdl->phdl != NULL) {
            (void) she_close_utils(hdl);
            if (hdl->cipher_handle != 0u) {
                (void)sab_close_cipher(hdl->phdl, hdl->cipher_handle);
            }
            if (hdl->rng_handle != 0u) {
                (void)sab_close_rng(hdl->phdl, hdl->rng_handle);
            }
            if (hdl->key_store_handle != 0u) {
                (void)sab_close_key_store(hdl->phdl, hdl->key_store_handle);
                hdl->key_store_handle = 0u;
            }
            if (hdl -> session_handle != 0u) {
                (void)sab_close_session_command (hdl->phdl, hdl->session_handle);
                hdl -> session_handle = 0u;
            }
            seco_os_abs_close_session(hdl->phdl);
            hdl->phdl = NULL;
        }
        seco_os_abs_free(hdl);
    }
}

uint32_t she_storage_create(uint32_t key_storage_identifier, uint32_t authentication_nonce, uint16_t max_updates_number, uint8_t *signed_message, uint32_t msg_len)
{
    struct she_hdl_s *hdl = NULL;
    uint32_t ret = SHE_STORAGE_CREATE_FAIL;
    uint32_t err;
    struct seco_mu_params mu_params;

    do {
        /* TODO: send the signed message to SECO if provided here. */
        if ((signed_message != NULL) || (msg_len != 0u)) {
            break;
        }

        /* allocate the handle (free when closing the session). */
        hdl = (struct she_hdl_s *)seco_os_abs_malloc((uint32_t)sizeof(struct she_hdl_s));
        if (hdl == NULL) {
            break;
        }
        seco_os_abs_memset((uint8_t *)hdl, 0u, (uint32_t)sizeof(struct she_hdl_s));

        /* Open the SHE session on the SHE kernel driver */
        hdl->phdl = seco_os_abs_open_mu_channel(MU_CHANNEL_SHE, &mu_params);
        if (hdl->phdl == NULL) {
            break;
        }

        /* Open the SHE session on SECO side */
        err = sab_open_session_command(hdl->phdl,
                                       &hdl->session_handle,
                                       mu_params.mu_id,
                                       mu_params.interrupt_idx,
                                       mu_params.tz,
                                       mu_params.did,
                                       mu_params.priority,
                                       mu_params.operating_mode);
        if (err != SAB_SUCCESS_STATUS) {
            hdl->session_handle = 0u;
            break;
        }

        /* Create the SHE keystore */
        err = sab_open_key_store_command(hdl->phdl,
                                         hdl->session_handle,
                                         &hdl->key_store_handle,
                                         key_storage_identifier,
                                         authentication_nonce,
                                         max_updates_number,
                                         KEY_STORE_OPEN_FLAGS_CREATE | KEY_STORE_OPEN_FLAGS_SHE);

        /* Interpret Seco status code*/
        if (GET_STATUS_CODE(err) == SAB_SUCCESS_STATUS) {
            if (GET_RATING_CODE(err) == SAB_INVALID_LIFECYCLE_RATING) {
                ret = SHE_STORAGE_CREATE_WARNING;
            } else {
                ret = SHE_STORAGE_CREATE_SUCCESS;
            }
        } else {
            hdl->key_store_handle = 0u;
            if (GET_RATING_CODE(err) == SAB_INVALID_LIFECYCLE_RATING) {
                ret = SHE_STORAGE_CREATE_UNAUTHORIZED;
            } else {
                ret = SHE_STORAGE_CREATE_FAIL;
            }
        }
    } while (false);

    if (hdl != NULL) {
        she_close_session(hdl);
    }
    return ret;
}

/* Open a SHE user session and return a pointer to the session handle. */
struct she_hdl_s *she_open_session(uint32_t key_storage_identifier, uint32_t authentication_nonce, void (*async_cb)(void *priv, she_err_t err), void *priv)
{
    struct she_hdl_s *hdl = NULL;
    uint32_t err = SAB_FAILURE_STATUS;
    struct seco_mu_params mu_params;

    do {
        if((async_cb != NULL) || (priv != NULL)) {
            /* not supported yet. */
            break;
        }
        /* allocate the handle (free when closing the session). */
        hdl = (struct she_hdl_s *)seco_os_abs_malloc((uint32_t)sizeof(struct she_hdl_s));
        if (hdl == NULL) {
            break;
        }
        seco_os_abs_memset((uint8_t *)hdl, 0u, (uint32_t)sizeof(struct she_hdl_s));

        /* Open the SHE session on the MU */
        hdl->phdl = seco_os_abs_open_mu_channel(MU_CHANNEL_SHE, &mu_params);
        if (hdl->phdl == NULL) {
            break;
        }

        /* Open the SHE session on SECO side */
        err = sab_open_session_command(hdl->phdl,
                                       &hdl->session_handle,
                                       mu_params.mu_id,
                                       mu_params.interrupt_idx,
                                       mu_params.tz,
                                       mu_params.did,
                                       mu_params.priority,
                                       mu_params.operating_mode);
        if (err != SAB_SUCCESS_STATUS) {
            hdl->session_handle = 0u;
            break;
        }

        /* Get a SECURE RAM partition to be used as shared buffer */
        err = sab_get_shared_buffer(hdl->phdl, hdl->session_handle);
        if (err != SAB_SUCCESS_STATUS) {
            break;
        }
        /* Get the access to the SHE keystore */
        err = sab_open_key_store_command(hdl->phdl,
                                         hdl->session_handle,
                                         &hdl->key_store_handle,
                                         key_storage_identifier,
                                         authentication_nonce,
                                         0u,
                                         KEY_STORE_OPEN_FLAGS_SHE);
        if (err != SAB_SUCCESS_STATUS) {
            hdl->key_store_handle = 0u;
            break;
        }

        /* open SHE utils service. */
        if (she_open_utils(hdl) != ERC_NO_ERROR) {
            break;
        }

        /* open cipher service. */
        err = sab_open_cipher(hdl->phdl,
                              hdl->key_store_handle,
                              &hdl->cipher_handle,
                              CIPHER_OPEN_FLAGS_DEFAULT);
        if (err != SAB_SUCCESS_STATUS) {
            hdl->cipher_handle = 0u;
            break;
        }
    } while (false);

    /* Clean-up in case of error. */
    if ((err != SAB_SUCCESS_STATUS) && (hdl != NULL)) {
        she_close_session(hdl);
        hdl = NULL;
    }
    return hdl;
};

/* MAC generation command processing. */
she_err_t she_cmd_generate_mac(struct she_hdl_s *hdl, uint8_t key_ext, uint8_t key_id, uint16_t message_length, uint8_t *message, uint8_t *mac)
{
    struct sab_she_fast_mac_msg cmd;
    struct sab_she_fast_mac_rsp rsp;
    int32_t error;
    she_err_t ret = ERC_GENERAL_ERROR;

    do {
        if ((hdl == NULL) || ((message == NULL) && (message_length != 0u)) || (mac == NULL)) {
            break;
        }
        /* Build command message. */
        seco_fill_cmd_msg_hdr(&cmd.hdr, SAB_FAST_MAC_REQ, (uint32_t)sizeof(struct sab_she_fast_mac_msg));
        cmd.she_utils_handle = hdl->utils_handle;
        cmd.key_id = (uint16_t)key_ext | (uint16_t)key_id;
        cmd.data_length = message_length;
        cmd.data_offset = (uint16_t)(seco_os_abs_data_buf(hdl->phdl, message, message_length, DATA_BUF_IS_INPUT | DATA_BUF_USE_SEC_MEM | DATA_BUF_SHORT_ADDR) & SEC_MEM_SHORT_ADDR_MASK);
        (void)(seco_os_abs_data_buf(hdl->phdl, mac, SHE_MAC_SIZE, DATA_BUF_USE_SEC_MEM | DATA_BUF_SHORT_ADDR) & SEC_MEM_SHORT_ADDR_MASK);
        cmd.mac_length = 0u;
        cmd.flags = 0u;

        /* Send the message to Seco. */
        error = seco_send_msg_and_get_resp(hdl->phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_she_fast_mac_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_she_fast_mac_rsp));
        if (error != 0) {
            break;
        }

        hdl->last_rating = rsp.rsp_code;
        if ((hdl->cancel != 0u) || (GET_STATUS_CODE(rsp.rsp_code) != SAB_SUCCESS_STATUS)) {
            ret = she_seco_ind_to_she_err_t(rsp.rsp_code);
            seco_os_abs_memset(mac, 0u, SHE_MAC_SIZE);
            hdl->cancel = 0u;
            break;
        }

        /* Success. */
        ret = ERC_NO_ERROR;
    } while (false);

    return ret;
}

/* MAC verify command processing. */
she_err_t she_cmd_verify_mac(struct she_hdl_s *hdl, uint8_t key_ext, uint8_t key_id, uint16_t message_length, uint8_t *message, uint8_t *mac, uint8_t mac_length, uint8_t *verification_status)
{
    struct sab_she_fast_mac_msg cmd;
    struct sab_she_fast_mac_rsp rsp;
    int32_t error;
    she_err_t ret = ERC_GENERAL_ERROR;

    do {
        if (verification_status == NULL) {
            break;
        }
        /* Force the status to fail in case of processing error. */
        *verification_status = SHE_MAC_VERIFICATION_FAILED;

        if ((hdl == NULL) || ((message == NULL) && (message_length != 0u)) || (mac == NULL)) {
            break;
        }
        /* Build command message. */
        seco_fill_cmd_msg_hdr(&cmd.hdr, SAB_FAST_MAC_REQ, (uint32_t)sizeof(struct sab_she_fast_mac_msg));
        cmd.she_utils_handle = hdl->utils_handle;
        cmd.key_id = (uint16_t)key_ext | (uint16_t)key_id;
        cmd.data_length = message_length;
        cmd.data_offset = (uint16_t)(seco_os_abs_data_buf(hdl->phdl, message, message_length, DATA_BUF_IS_INPUT | DATA_BUF_USE_SEC_MEM | DATA_BUF_SHORT_ADDR) & SEC_MEM_SHORT_ADDR_MASK);
        (void)(seco_os_abs_data_buf(hdl->phdl, mac, SHE_MAC_SIZE, DATA_BUF_IS_INPUT | DATA_BUF_USE_SEC_MEM | DATA_BUF_SHORT_ADDR) & SEC_MEM_SHORT_ADDR_MASK);
        cmd.mac_length = mac_length;
        cmd.flags = SAB_SHE_FAST_MAC_FLAGS_VERIFICATION;

        /* Send the message to Seco. */
        error = seco_send_msg_and_get_resp(hdl->phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_she_fast_mac_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_she_fast_mac_rsp));
        if (error != 0) {
            break;
        }

        hdl->last_rating = rsp.rsp_code;
        if ((hdl->cancel != 0u) || (GET_STATUS_CODE(rsp.rsp_code) != SAB_SUCCESS_STATUS)) {
            ret = she_seco_ind_to_she_err_t(rsp.rsp_code);
            *verification_status = SHE_MAC_VERIFICATION_FAILED;
            hdl->cancel = 0u;
            break;
        }
        /* Command success: Report the verification status. */
        *verification_status = (rsp.verification_status == SAB_SHE_FAST_MAC_VERIFICATION_STATUS_OK ? SHE_MAC_VERIFICATION_SUCCESS : SHE_MAC_VERIFICATION_FAILED);
        ret = ERC_NO_ERROR;
    } while (false);

    return ret;
}

/* Generic function for encryption and decryption. */
static she_err_t she_cmd_cipher_one_go(struct she_hdl_s *hdl, uint8_t key_ext, uint8_t key_id, uint32_t input_length, uint32_t output_length, uint8_t *iv, uint8_t *input, uint8_t *output, uint8_t flags, uint8_t algo)
{
    struct sab_cmd_cipher_one_go_msg cmd;
    struct sab_cmd_cipher_one_go_rsp rsp;
    int32_t error;
    uint64_t seco_iv_addr, seco_input_addr, seco_output_addr;
    uint16_t iv_size;
    she_err_t ret = ERC_GENERAL_ERROR;

    do {
        if ((hdl == NULL) || (input == NULL) || (output == NULL)) {
            break;
        }
        /* Build command message. */
        seco_fill_cmd_msg_hdr(&cmd.hdr, SAB_CIPHER_ONE_GO_REQ, (uint32_t)sizeof(struct sab_cmd_cipher_one_go_msg));
        cmd.cipher_handle = hdl->cipher_handle;
        cmd.key_id = (uint32_t)key_ext | (uint32_t)key_id;
        cmd.algo = algo;
        cmd.flags = flags;

        if (algo == AHAB_CIPHER_ONE_GO_ALGO_ECB) {
            seco_iv_addr = 0;
            iv_size = 0;
        }
        else if (algo == AHAB_CIPHER_ONE_GO_ALGO_CBC) {
            if (iv == NULL) {
                break;
            }
            seco_iv_addr = seco_os_abs_data_buf(hdl->phdl, iv, SHE_AES_BLOCK_SIZE_128, DATA_BUF_IS_INPUT);
            iv_size = SHE_AES_BLOCK_SIZE_128;
        } else {
            break;
        }

        seco_input_addr = seco_os_abs_data_buf(hdl->phdl, input, input_length, DATA_BUF_IS_INPUT);
        seco_output_addr = seco_os_abs_data_buf(hdl->phdl, output, output_length, 0u);

        /* Keep same layout in secure ram even for algos not using IV to simplify code here. */
        cmd.iv_address = (uint32_t)(seco_iv_addr & 0xFFFFFFFFu);
        cmd.input_address = (uint32_t)(seco_input_addr & 0xFFFFFFFFu);
        cmd.output_address = (uint32_t)(seco_output_addr & 0xFFFFFFFFu);
        cmd.input_length = input_length;
        cmd.output_length = output_length;
        cmd.iv_size = iv_size;
        cmd.crc = seco_compute_msg_crc((uint32_t*)&cmd, (uint32_t)(sizeof(cmd) - sizeof(uint32_t)));


        /* Send the message to Seco. */
        error = seco_send_msg_and_get_resp(hdl->phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_cmd_cipher_one_go_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_cmd_cipher_one_go_rsp));
        if (error != 0) {
            break;
        }

        hdl->last_rating = rsp.rsp_code;
        if ((hdl->cancel != 0u) || (GET_STATUS_CODE(rsp.rsp_code) != SAB_SUCCESS_STATUS)) {
            ret = she_seco_ind_to_she_err_t(rsp.rsp_code);
            seco_os_abs_memset(output, 0u, output_length);
            hdl->cancel = 0u;
            break;
        }

        ret = ERC_NO_ERROR;
    } while (false);

    return ret;
}

/* CBC encrypt command. */
she_err_t she_cmd_enc_cbc(struct she_hdl_s *hdl, uint8_t key_ext, uint8_t key_id, uint32_t data_length, uint8_t *iv, uint8_t *plaintext, uint8_t *ciphertext)
{
    return she_cmd_cipher_one_go(hdl, key_ext, key_id, data_length, data_length, iv, plaintext, ciphertext, AHAB_CIPHER_ONE_GO_FLAGS_ENCRYPT, AHAB_CIPHER_ONE_GO_ALGO_CBC);
}

/* CBC decrypt command. */
she_err_t she_cmd_dec_cbc(struct she_hdl_s *hdl, uint8_t key_ext, uint8_t key_id, uint32_t data_length, uint8_t *iv, uint8_t *ciphertext, uint8_t *plaintext)
{
    return she_cmd_cipher_one_go(hdl, key_ext, key_id, data_length, data_length, iv, ciphertext, plaintext, AHAB_CIPHER_ONE_GO_FLAGS_DECRYPT, AHAB_CIPHER_ONE_GO_ALGO_CBC);
}

/* ECB encrypt command. */
she_err_t she_cmd_enc_ecb(struct she_hdl_s *hdl, uint8_t key_ext, uint8_t key_id, uint8_t *plaintext, uint8_t *ciphertext)
{
    return she_cmd_cipher_one_go(hdl, key_ext, key_id, SHE_AES_BLOCK_SIZE_128, SHE_AES_BLOCK_SIZE_128, NULL, plaintext, ciphertext, AHAB_CIPHER_ONE_GO_FLAGS_ENCRYPT, AHAB_CIPHER_ONE_GO_ALGO_ECB);
}

/* ECB decrypt command. */
she_err_t she_cmd_dec_ecb(struct she_hdl_s *hdl, uint8_t key_ext, uint8_t key_id, uint8_t *ciphertext, uint8_t *plaintext)
{
    return she_cmd_cipher_one_go(hdl, key_ext, key_id, SHE_AES_BLOCK_SIZE_128, SHE_AES_BLOCK_SIZE_128, NULL, ciphertext, plaintext, AHAB_CIPHER_ONE_GO_FLAGS_DECRYPT, AHAB_CIPHER_ONE_GO_ALGO_ECB);
}

/* Load key command processing. */
she_err_t she_cmd_load_key(struct she_hdl_s *hdl, uint8_t key_ext, uint8_t key_id, uint8_t *m1, uint8_t *m2, uint8_t *m3, uint8_t *m4, uint8_t *m5)
{
    struct sab_she_key_update_msg cmd;
    struct sab_she_key_update_rsp rsp;
    int32_t error;
    she_err_t ret = ERC_GENERAL_ERROR;

    do {
        if ((hdl == NULL) || (m1 == NULL) || (m2 == NULL) || (m3 == NULL) || (m4 == NULL) || (m5 == NULL)) {
            break;
        }
        if (hdl->utils_handle == 0u) {
            ret = ERC_SEQUENCE_ERROR;
            break;
        }
        /* Build command message. */
        seco_fill_cmd_msg_hdr(&cmd.hdr, SAB_SHE_KEY_UPDATE, (uint32_t)sizeof(struct sab_she_key_update_msg));
        cmd.utils_handle = hdl->utils_handle;
        cmd.key_id = (uint32_t)key_ext | (uint32_t)key_id;
        seco_os_abs_memcpy((uint8_t *)cmd.m1, m1, SHE_KEY_SIZE);
        seco_os_abs_memcpy((uint8_t *)cmd.m2, m2, 2u * SHE_KEY_SIZE);
        seco_os_abs_memcpy((uint8_t *)cmd.m3, m3, SHE_KEY_SIZE);
        cmd.crc = seco_compute_msg_crc((uint32_t*)&cmd, (uint32_t)(sizeof(cmd) - sizeof(uint32_t)));

        /* Send the message to Seco. */
        error = seco_send_msg_and_get_resp(hdl->phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_she_key_update_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_she_key_update_rsp));
        if (error != 0) {
            break;
        }

        hdl->last_rating = rsp.rsp_code;
        if ((hdl->cancel != 0u)
            || (GET_STATUS_CODE(rsp.rsp_code)!= SAB_SUCCESS_STATUS)
            || (rsp.crc != seco_compute_msg_crc((uint32_t*)&rsp, (uint32_t)(sizeof(rsp) - sizeof(uint32_t))))) {
            ret = she_seco_ind_to_she_err_t(rsp.rsp_code);
            seco_os_abs_memset(m4, 0u, 2u * SHE_KEY_SIZE);
            seco_os_abs_memset(m5, 0u, SHE_KEY_SIZE);
            hdl->cancel = 0u;
            break;
        }

        /* Success: copy m4 and m5 reported by SECO to output.*/
        seco_os_abs_memcpy(m4, (uint8_t *)rsp.m4, 2u * SHE_KEY_SIZE);
        seco_os_abs_memcpy(m5, (uint8_t *)rsp.m5, SHE_KEY_SIZE);

        /* Success. */
        ret = ERC_NO_ERROR;
    } while (false);

    return ret;
}

she_err_t she_cmd_load_plain_key(struct she_hdl_s *hdl, uint8_t *key) 
{
    struct she_cmd_load_plain_key_msg cmd;
    struct she_cmd_load_plain_key_rsp rsp;
    int32_t error;
    she_err_t ret = ERC_GENERAL_ERROR;

    do {
        if ((hdl == NULL) || (key == NULL)) {
            break;
        }
        /* Build command message. */
        seco_fill_cmd_msg_hdr(&cmd.hdr, SAB_SHE_PLAIN_KEY_UPDATE, (uint32_t)sizeof(struct she_cmd_load_plain_key_msg));

        seco_os_abs_memcpy(cmd.key, key, SHE_KEY_SIZE);
        cmd.she_utils_handle = hdl->utils_handle;
        cmd.crc = seco_compute_msg_crc((uint32_t*)&cmd, (uint32_t)(sizeof(cmd) - sizeof(uint32_t)));

        /* Send the message to Seco. */
        error = seco_send_msg_and_get_resp(hdl->phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct she_cmd_load_plain_key_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct she_cmd_load_plain_key_rsp));
        if (error != 0) {
            break;
        }

        hdl->last_rating = rsp.rsp_code;
        if ((hdl->cancel != 0u) || (GET_STATUS_CODE(rsp.rsp_code)!= SAB_SUCCESS_STATUS)) {
            ret = she_seco_ind_to_she_err_t(rsp.rsp_code);
            hdl->cancel = 0u;
            break;
        }

        /* Success. */
        ret = ERC_NO_ERROR;
    } while (false);

    return ret;
}

she_err_t she_cmd_export_ram_key(struct she_hdl_s *hdl, uint8_t *m1, uint8_t *m2, uint8_t *m3, uint8_t *m4, uint8_t *m5) {

    struct sab_she_plain_key_export_msg cmd;
    struct sab_she_plain_key_export_rsp rsp;
    int32_t error;
    she_err_t ret = ERC_GENERAL_ERROR;

    do {
        if ((hdl == NULL) || (m1 == NULL) || (m2 == NULL) || (m3 == NULL) || (m4 == NULL) || (m5 == NULL)) {
            break;
        }
        if (hdl->utils_handle == 0u) {
            ret = ERC_SEQUENCE_ERROR;
            break;
        }
        /* Build command message. */
        seco_fill_cmd_msg_hdr(&cmd.hdr, SAB_SHE_PLAIN_KEY_EXPORT, (uint32_t)sizeof(struct sab_she_plain_key_export_msg));
        cmd.utils_handle = hdl->utils_handle;

        /* Send the message to Seco. */
        error = seco_send_msg_and_get_resp(hdl->phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_she_plain_key_export_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_she_plain_key_export_rsp));
        if (error != 0) {
            break;
        }

        hdl->last_rating = rsp.rsp_code;
        if ((hdl->cancel != 0u)
            || (GET_STATUS_CODE(rsp.rsp_code)!= SAB_SUCCESS_STATUS)
            || (rsp.crc != seco_compute_msg_crc((uint32_t*)&rsp, (uint32_t)(sizeof(rsp) - sizeof(uint32_t))))) {
            ret = she_seco_ind_to_she_err_t(rsp.rsp_code);
            seco_os_abs_memset(m1, 0u, SHE_KEY_SIZE);
            seco_os_abs_memset(m2, 0u, 2u * SHE_KEY_SIZE);
            seco_os_abs_memset(m3, 0u, SHE_KEY_SIZE);
            seco_os_abs_memset(m4, 0u, 2u * SHE_KEY_SIZE);
            seco_os_abs_memset(m5, 0u, SHE_KEY_SIZE);
            hdl->cancel = 0u;
            break;
        }

        /* Success: copy m1..m5 reported by SECO to output.*/
        seco_os_abs_memcpy(m1, (uint8_t *)rsp.m1, SHE_KEY_SIZE);
        seco_os_abs_memcpy(m2, (uint8_t *)rsp.m2, 2u * SHE_KEY_SIZE);
        seco_os_abs_memcpy(m3, (uint8_t *)rsp.m3, SHE_KEY_SIZE);
        seco_os_abs_memcpy(m4, (uint8_t *)rsp.m4, 2u * SHE_KEY_SIZE);
        seco_os_abs_memcpy(m5, (uint8_t *)rsp.m5, SHE_KEY_SIZE);

        /* Success. */
        ret = ERC_NO_ERROR;
    } while (false);

    return ret;
}

she_err_t she_cmd_init_rng(struct she_hdl_s *hdl) {
    uint32_t seco_rsp_code;
    she_err_t ret = ERC_GENERAL_ERROR;

    do {
        if (hdl == NULL) {
            break;
        }
        /* Start the RNG at system level. */
        seco_os_abs_start_system_rng(hdl->phdl);

        /* Then send the command to SECO so it can perform its own RNG inits. */
        seco_rsp_code = sab_open_rng(hdl->phdl, hdl->session_handle, &hdl->rng_handle, RNG_OPEN_FLAGS_SHE);

        if ((hdl->cancel != 0u) || (GET_STATUS_CODE(seco_rsp_code)!= SAB_SUCCESS_STATUS)) {
            hdl->rng_handle = 0u;
            ret = she_seco_ind_to_she_err_t(seco_rsp_code);
            hdl->cancel = 0u;
            break;
        }

        ret = ERC_NO_ERROR;
    } while(false);
    return ret;
}


she_err_t she_cmd_extend_seed(struct she_hdl_s *hdl, uint8_t *entropy) {
    struct sab_cmd_extend_seed_msg cmd;
    struct sab_cmd_extend_seed_rsp rsp;
    int32_t error;
    she_err_t ret = ERC_GENERAL_ERROR;

    do {
        if ((hdl == NULL) || (entropy == NULL)) {
            break;
        }
        if (hdl->rng_handle == 0u) {
            ret = ERC_SEQUENCE_ERROR;
            break;
        }
        /* Build command message. */
        seco_fill_cmd_msg_hdr(&cmd.hdr, SAB_RNG_EXTEND_SEED, (uint32_t)sizeof(struct sab_cmd_extend_seed_msg));
        cmd.rng_handle = hdl->rng_handle;
        seco_os_abs_memcpy((uint8_t *)cmd.entropy, entropy, SHE_ENTROPY_SIZE);
        cmd.crc = seco_compute_msg_crc((uint32_t*)&cmd, (uint32_t)(sizeof(cmd) - sizeof(uint32_t)));

        /* Send the message to Seco. */
        error = seco_send_msg_and_get_resp(hdl->phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_cmd_extend_seed_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_cmd_extend_seed_rsp));
        if (error != 0) {
            break;
        }

        hdl->last_rating = rsp.rsp_code;
        if ((hdl->cancel != 0u) || (GET_STATUS_CODE(rsp.rsp_code)!= SAB_SUCCESS_STATUS)) {
            ret = she_seco_ind_to_she_err_t(rsp.rsp_code);
            hdl->cancel = 0u;
            break;
        }

        /* Success. */
        ret = ERC_NO_ERROR;
    } while (false);

    return ret;
}


she_err_t she_cmd_rnd(struct she_hdl_s *hdl, uint8_t *rnd)
{
    she_err_t ret = ERC_GENERAL_ERROR;
    struct sab_cmd_get_rnd_msg cmd;
    struct sab_cmd_get_rnd_rsp rsp;
    uint64_t seco_rnd_addr;
    int32_t error;

    do {
        if ((hdl == NULL) || (rnd == NULL)) {
            break;
        }
        if (hdl->rng_handle == 0u) {
            ret = ERC_SEQUENCE_ERROR;
            break;
        }

        /* Build command message. */
        seco_fill_cmd_msg_hdr(&cmd.hdr, SAB_RNG_GET_RANDOM, (uint32_t)sizeof(struct sab_cmd_get_rnd_msg));
        seco_rnd_addr = seco_os_abs_data_buf(hdl->phdl, rnd, SHE_RND_SIZE, 0u);
        cmd.rng_handle = hdl->rng_handle;
        cmd.rnd_addr = (uint32_t)(seco_rnd_addr & 0xFFFFFFFFu);
        cmd.rnd_size = SHE_RND_SIZE;

        /* Send the message to Seco. */
        error = seco_send_msg_and_get_resp(hdl->phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_cmd_get_rnd_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_cmd_get_rnd_rsp));
        if (error != 0) {
            break;
        }

        hdl->last_rating = rsp.rsp_code;
        if ((hdl->cancel != 0u) || (GET_STATUS_CODE(rsp.rsp_code)!= SAB_SUCCESS_STATUS)) {
            ret = she_seco_ind_to_she_err_t(rsp.rsp_code);
            seco_os_abs_memset(rnd, 0u, SHE_RND_SIZE);
            hdl->cancel = 0u;
            break;
        }

        /* Success. */
        ret = ERC_NO_ERROR;
    } while (false);

    return ret;
}


she_err_t she_cmd_get_status(struct she_hdl_s *hdl, uint8_t *sreg) {
    struct she_cmd_get_status_msg cmd;
    struct she_cmd_get_status_rsp rsp;
    int32_t error;
    she_err_t ret = ERC_GENERAL_ERROR;

    do {
        if ((hdl == NULL) || (sreg == NULL)) {
            break;
        }
        /* Build command message. */
        seco_fill_cmd_msg_hdr(&cmd.hdr, SAB_SHE_GET_STATUS, (uint32_t)sizeof(struct she_cmd_get_status_msg));
        cmd.she_utils_handle = hdl->utils_handle;

        /* Send the message to Seco. */
        error = seco_send_msg_and_get_resp(hdl->phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct she_cmd_get_status_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct she_cmd_get_status_rsp));
        if (error != 0) {
            break;
        }

        hdl->last_rating = rsp.rsp_code;
        if ((hdl->cancel != 0u) || (GET_STATUS_CODE(rsp.rsp_code)!= SAB_SUCCESS_STATUS)) {
            ret = she_seco_ind_to_she_err_t(rsp.rsp_code);
            *sreg = 0;
            hdl->cancel = 0u;
            break;
        }

        /* Success: write sreg reported by SECO to output.*/
        *sreg = rsp.sreg;

        /* Success. */
        ret = ERC_NO_ERROR;
    } while (false);

    return ret;
}


she_err_t she_cmd_get_id(struct she_hdl_s *hdl, uint8_t *challenge, uint8_t *id, uint8_t *sreg, uint8_t *mac) {
    struct she_cmd_get_id_msg cmd;
    struct she_cmd_get_id_rsp rsp;
    int32_t error;
    she_err_t ret = ERC_GENERAL_ERROR;

    do {
        if ((hdl == NULL) || (challenge == NULL) || (id == NULL) || (sreg == NULL) || (mac == NULL)) {
            break;
        }
        /* Build command message. */
        seco_fill_cmd_msg_hdr(&cmd.hdr, SAB_SHE_GET_ID, (uint32_t)sizeof(struct she_cmd_get_id_msg));
        seco_os_abs_memcpy(cmd.challenge, challenge, SHE_CHALLENGE_SIZE);
        cmd.she_utils_handle = hdl->utils_handle;
        cmd.crc = seco_compute_msg_crc((uint32_t*)&cmd, (uint32_t)(sizeof(cmd) - sizeof(uint32_t)));

        /* Send the message to Seco. */
        error = seco_send_msg_and_get_resp(hdl->phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct she_cmd_get_id_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct she_cmd_get_id_rsp));
        if (error != 0) {
            break;
        }

        hdl->last_rating = rsp.rsp_code;
        if ((hdl->cancel != 0u)
            || (GET_STATUS_CODE(rsp.rsp_code)!= SAB_SUCCESS_STATUS)
            || (rsp.crc != seco_compute_msg_crc((uint32_t*)&rsp, (uint32_t)(sizeof(rsp) - sizeof(uint32_t))))) {
            ret = she_seco_ind_to_she_err_t(rsp.rsp_code);
            *sreg = 0;
            seco_os_abs_memset(id, 0u, SHE_ID_SIZE);
            seco_os_abs_memset(mac, 0u, SHE_MAC_SIZE);
            hdl->cancel = 0u;
            break;
        }

        /* Success: copy sreg , id and cmac reported by SECO to output.*/
        *sreg = rsp.sreg;
        seco_os_abs_memcpy(id, rsp.id, SHE_ID_SIZE);
        seco_os_abs_memcpy(mac, rsp.mac, SHE_MAC_SIZE);

        /* Success. */
        ret = ERC_NO_ERROR;
    } while (false);

    return ret;
}


she_err_t she_cmd_cancel(struct she_hdl_s *hdl) {
    she_err_t ret = ERC_GENERAL_ERROR;
    if (hdl != NULL) {
        hdl->cancel = 1u;
        ret = ERC_NO_ERROR;
    }

    return ret;
}

uint32_t she_get_last_rating_code(struct she_hdl_s *hdl)
{
    uint32_t ret = 0xFFFFFFFFu;

    if (hdl != NULL) {
        ret = hdl->last_rating;
    }
    return ret;
}


she_err_t she_get_info(struct she_hdl_s *hdl, uint32_t *user_sab_id, uint8_t *chip_unique_id, uint16_t *chip_monotonic_counter, uint16_t *chip_life_cycle, uint32_t *she_version) {
    struct she_cmd_get_id_msg cmd;
    struct she_cmd_get_id_rsp rsp;
    uint32_t seco_rsp_code;
    she_err_t ret = ERC_GENERAL_ERROR;
    uint32_t version_ext;
    uint8_t fips_mode;

    do {
        if ((hdl == NULL) || (user_sab_id == NULL) || (chip_unique_id == NULL) || (chip_monotonic_counter == NULL) || (chip_life_cycle == NULL) || (she_version == NULL)) {
            break;
        }
        seco_rsp_code = sab_get_info(hdl->phdl, hdl->session_handle, user_sab_id, chip_unique_id, chip_monotonic_counter, chip_life_cycle, she_version, &version_ext, &fips_mode);

        if (GET_STATUS_CODE(seco_rsp_code) != SAB_SUCCESS_STATUS) {
            ret = she_seco_ind_to_she_err_t(seco_rsp_code);
            break;
        }

        /* Success. */
        ret = ERC_NO_ERROR;
    } while (false);

    return ret;
}
