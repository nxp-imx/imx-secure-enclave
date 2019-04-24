
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
#include "messaging.h"

#define SHE_DEFAULT_DID                     0x0u
#define SHE_DEFAULT_TZ                      0x0u
#define SHE_DEFAULT_MU                      0x1u
#define SHE_DEFAULT_INTERRUPT_IDX           0x0u
#define SHE_DEFAULT_PRIORITY                0x0u
#define SHE_DEFAULT_OPERATING_MODE          0x0u
#define SHE_DEFAULT_KEY_STORE_OPEN_FLAGS    0x0u
#define SHE_DEFAULT_CIPHER_OPEN_FLAGS       0x0u
#define SHE_DEFAULT_RNG_OPEN_FLAGS          0x1u

struct she_hdl_s {
    struct she_platform_hdl *phdl;
    uint32_t session_handle;
    uint32_t key_store_handle;
    uint32_t cipher_handle;
    uint32_t rng_handle;
    uint32_t utils_handle;
    uint32_t cancel;
};

static she_err_t she_open_key_store(struct she_hdl_s *hdl, uint32_t key_storage_identifier, uint32_t password)
{
    struct sab_cmd_key_store_open_msg cmd;
    struct sab_cmd_key_store_open_rsp rsp;

    she_err_t ret = ERC_GENERAL_ERROR;
    int32_t error = 1;
    do {

        if (hdl->session_handle == 0u) {
            break;
        }

        /* Send the keys store open command to Seco. */
        she_fill_cmd_msg_hdr(&cmd.hdr, SAB_KEY_STORE_OPEN_REQ, (uint32_t)sizeof(struct sab_cmd_key_store_open_msg));

        cmd.sesssion_handle = hdl->session_handle;
        cmd.key_store_id = key_storage_identifier;
        cmd.password = password;
        cmd.flags = SHE_DEFAULT_KEY_STORE_OPEN_FLAGS;
        cmd.crc = she_compute_msg_crc((uint32_t*)&cmd, (uint32_t)(sizeof(cmd) - sizeof(uint32_t)));

        error = she_send_msg_and_get_resp(hdl->phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_cmd_key_store_open_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_cmd_key_store_open_rsp));

        if (error != 0) {
            break;
        }

        if (GET_STATUS_CODE(rsp.rsp_code) != SAB_SUCCESS_STATUS) {
            ret = she_seco_ind_to_she_err_t(rsp.rsp_code);
            break;
        }

        hdl->key_store_handle = rsp.key_store_handle;
        /* Success. */
        ret = ERC_NO_ERROR;
    } while(false);
    return ret;
}

static she_err_t she_close_key_store(struct she_hdl_s *hdl)
{
    struct sab_cmd_key_store_close_msg cmd;
    struct sab_cmd_key_store_close_rsp rsp;
    she_err_t ret = ERC_GENERAL_ERROR;
    int32_t error = 1;
    do {

        if (hdl->key_store_handle == 0u) {
            break;
        }
        /* Send the keys store close command to Seco. */
        she_fill_cmd_msg_hdr(&cmd.hdr, SAB_KEY_STORE_CLOSE_REQ, (uint32_t)sizeof(struct sab_cmd_key_store_close_msg));
        cmd.key_store_handle = hdl->key_store_handle;

        error = she_send_msg_and_get_resp(hdl->phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_cmd_key_store_close_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_cmd_key_store_close_rsp));

        if (error != 0) {
            break;
        }

        if (GET_STATUS_CODE(rsp.rsp_code)!= SAB_SUCCESS_STATUS) {
            ret = she_seco_ind_to_she_err_t(rsp.rsp_code);
            break;
        }

        hdl->key_store_handle = 0;

        /* Success. */
        ret = ERC_NO_ERROR;
    } while(false);
    return ret;
}

static she_err_t she_open_cipher(struct she_hdl_s *hdl)
{
    struct sab_cmd_cipher_open_msg cmd;
    struct sab_cmd_cipher_open_rsp rsp;
    she_err_t ret = ERC_GENERAL_ERROR;
    int32_t error = 1;
    do {

        if (hdl->cipher_handle != 0u) {
            break;
        }
        /* Send the keys store open command to Seco. */
        she_fill_cmd_msg_hdr(&cmd.hdr, SAB_CIPHER_OPEN_REQ, (uint32_t)sizeof(struct sab_cmd_cipher_open_msg));
        cmd.input_address_ext = 0;
        cmd.output_address_ext = 0;
        cmd.flags = SHE_DEFAULT_CIPHER_OPEN_FLAGS;
        cmd.key_store_handle = hdl->key_store_handle;
        cmd.crc = she_compute_msg_crc((uint32_t*)&cmd, (uint32_t)(sizeof(cmd) - sizeof(uint32_t)));

        error = she_send_msg_and_get_resp(hdl->phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_cmd_cipher_open_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_cmd_cipher_open_rsp));

        if (error != 0) {
            break;
        }

        if (GET_STATUS_CODE(rsp.rsp_code) != SAB_SUCCESS_STATUS) {
            ret = she_seco_ind_to_she_err_t(rsp.rsp_code);
            break;
        }

        hdl->cipher_handle = rsp.cipher_handle;
        /* Success. */
        ret = ERC_NO_ERROR;
    } while(false);
    return ret;
}

static she_err_t she_close_cipher(struct she_hdl_s *hdl)
{
    struct sab_cmd_cipher_close_msg cmd;
    struct sab_cmd_cipher_close_rsp rsp;
    she_err_t ret = ERC_GENERAL_ERROR;
    int32_t error = 1;
    do {
        if (hdl->cipher_handle == 0u){
            break;
        }
        /* Send the keys store open command to Seco. */
        she_fill_cmd_msg_hdr(&cmd.hdr, SAB_CIPHER_CLOSE_REQ, (uint32_t)sizeof(struct sab_cmd_cipher_close_msg));
        cmd.cipher_handle = hdl->cipher_handle;
        error = she_send_msg_and_get_resp(hdl->phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_cmd_cipher_close_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_cmd_cipher_close_rsp));

        if (error != 0) {
            break;
        }

        if (GET_STATUS_CODE(rsp.rsp_code) != SAB_SUCCESS_STATUS) {
            ret = she_seco_ind_to_she_err_t(rsp.rsp_code);
            break;
        }

        hdl->cipher_handle = 0;
        /* Success. */
        ret = ERC_NO_ERROR;
    } while(false);

    return ret;
}

static she_err_t she_close_rng(struct she_hdl_s *hdl)
{
    struct sab_cmd_rng_close_msg cmd;
    struct sab_cmd_rng_close_rsp rsp;
    she_err_t ret = ERC_GENERAL_ERROR;
    int32_t error = 1;
    do {
        if (hdl->rng_handle == 0u){
            break;
        }
        /* Send the keys store open command to Seco. */
        she_fill_cmd_msg_hdr(&cmd.hdr, SAB_RNG_CLOSE_REQ, (uint32_t)sizeof(struct sab_cmd_rng_close_msg));
        cmd.rng_handle = hdl->rng_handle;
        error = she_send_msg_and_get_resp(hdl->phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_cmd_rng_close_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_cmd_rng_close_rsp));

        if (error != 0) {
            break;
        }

        if (GET_STATUS_CODE(rsp.rsp_code) != SAB_SUCCESS_STATUS) {
            ret = she_seco_ind_to_she_err_t(rsp.rsp_code);
            break;
        }

        hdl->cipher_handle = 0;
        /* Success. */
        ret = ERC_NO_ERROR;
    } while(false);
    return ret;
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
        she_fill_cmd_msg_hdr(&cmd.hdr, SAB_SHE_UTILS_OPEN, (uint32_t)sizeof(struct sab_cmd_she_utils_open_msg));
        cmd.input_address_ext = 0;
        cmd.output_address_ext = 0;
        cmd.key_store_handle = hdl->key_store_handle;

        error = she_send_msg_and_get_resp(hdl->phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_cmd_she_utils_open_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_cmd_she_utils_open_rsp));

        if (error != 0) {
            break;
        }

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
        she_fill_cmd_msg_hdr(&cmd.hdr, SAB_SHE_UTILS_CLOSE, (uint32_t)sizeof(struct sab_cmd_she_utils_close_msg));
        cmd.utils_handle = hdl->utils_handle;
        error = she_send_msg_and_get_resp(hdl->phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_cmd_she_utils_close_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_cmd_she_utils_close_rsp));

        if (error != 0) {
            break;
        }

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
            (void) she_close_rng(hdl);
            (void) she_close_key_store(hdl);
            if (hdl -> session_handle != 0u) {
                (void)she_close_session_command (hdl->phdl, hdl->session_handle);
                hdl -> session_handle = 0u;
            }
            she_platform_close_session(hdl->phdl);
            hdl->phdl = NULL;
        }
        she_platform_free(hdl);
    }
}

/* Open a SHE user session and return a pointer to the session handle. */
struct she_hdl_s *she_open_session(uint32_t key_storage_identifier, uint32_t password)
{
    struct she_hdl_s *hdl = NULL;
    int32_t error = 1;
    uint32_t shared_buf_offset, shared_buf_size;
    do {
        /* allocate the handle (free when closing the session). */
        hdl = (struct she_hdl_s *)she_platform_malloc((uint32_t)sizeof(struct she_hdl_s));
        if (hdl == NULL) {
            break;
        }
        she_platform_memset((uint8_t *)hdl, 0u, (uint32_t)sizeof(struct she_hdl_s));

        /* Open the SHE session on the SHE kernel driver */
        hdl->phdl = she_platform_open_she_session();
        if (hdl->phdl == NULL) {
            break;
        }

        /* Open the SHE session on SECO side */
        if (she_open_session_command (hdl->phdl, &hdl->session_handle, SHE_DEFAULT_MU,
                SHE_DEFAULT_INTERRUPT_IDX, SHE_DEFAULT_TZ, SHE_DEFAULT_DID, SHE_DEFAULT_PRIORITY,
                SHE_DEFAULT_OPERATING_MODE) != ERC_NO_ERROR) {
            break;
        }

        /* Get a SECURE RAM partition to be used as shared buffer */
        if (she_get_shared_buffer(hdl->phdl, hdl->session_handle, &shared_buf_offset, &shared_buf_size) != ERC_NO_ERROR) {
            break;
        }

        /* Configure the shared buffer. */
        error = she_platform_configure_shared_buf(hdl->phdl, shared_buf_offset, shared_buf_size);
        if (error != 0) {
            break;
        }

        /* Get the access to the SHE keystore */
        if(she_open_key_store(hdl, key_storage_identifier, password) != ERC_NO_ERROR) {
            break;
        }

        /* open cipher service. */
        if (she_open_utils(hdl) != ERC_NO_ERROR) {
            break;
        }
        /* Success. */
        error = 0;
    } while (false);

    /* Clean-up in case of error. */
    if ((error != 0) && (hdl != NULL)) {
        she_close_session(hdl);
        hdl = NULL;
    }
    return hdl;
};

/* MAC generation command processing. */
she_err_t she_cmd_generate_mac(struct she_hdl_s *hdl, uint8_t key_ext, uint8_t key_id, uint16_t message_length, uint8_t *message, uint8_t *mac)
{
    struct she_cmd_generate_mac_msg cmd;
    struct she_cmd_generate_mac_rsp rsp;
    int32_t error;
    she_err_t ret = ERC_GENERAL_ERROR;

    do {
        /* Build command message. */
        she_fill_cmd_msg_hdr(&cmd.hdr, SAB_FAST_MAC_REQ, (uint32_t)sizeof(struct she_cmd_generate_mac_msg));
        cmd.key_id = (uint16_t)key_ext | (uint16_t)key_id;
        cmd.data_length = message_length;
        cmd.data_offset = (uint16_t)(she_platform_data_buf(hdl->phdl, message, message_length, DATA_BUF_IS_INPUT | DATA_BUF_USE_SEC_MEM | DATA_BUF_SHORT_ADDR) & SEC_MEM_SHORT_ADDR_MASK);
        cmd.mac_offset = (uint16_t)(she_platform_data_buf(hdl->phdl, mac, SHE_MAC_SIZE, DATA_BUF_USE_SEC_MEM | DATA_BUF_SHORT_ADDR) & SEC_MEM_SHORT_ADDR_MASK);

        /* Send the message to Seco. */
        error = she_send_msg_and_get_resp(hdl->phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct she_cmd_generate_mac_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct she_cmd_generate_mac_rsp));
        if (error != 0) {
            break;
        }

        if ((hdl->cancel != 0u) || (GET_STATUS_CODE(rsp.rsp_code) != SAB_SUCCESS_STATUS)) {
            ret = she_seco_ind_to_she_err_t(rsp.rsp_code);
            she_platform_memset(mac, 0u, SHE_MAC_SIZE);
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
    struct she_cmd_verify_mac_msg cmd;
    struct she_cmd_verify_mac_rsp rsp;
    int32_t error;
    she_err_t ret = ERC_GENERAL_ERROR;

    do {
        /* Build command message. */
        she_fill_cmd_msg_hdr(&cmd.hdr, AHAB_SHE_CMD_VERIFY_MAC, (uint32_t)sizeof(struct she_cmd_verify_mac_msg));
        cmd.key_id = (uint16_t)key_ext | (uint16_t)key_id;
        cmd.data_length = message_length;
        /* input message at offset 0. MAC just after at offset "message_length". */
        cmd.data_offset = (uint16_t)(she_platform_data_buf(hdl->phdl, message, message_length, DATA_BUF_IS_INPUT | DATA_BUF_USE_SEC_MEM | DATA_BUF_SHORT_ADDR) & SEC_MEM_SHORT_ADDR_MASK);
        cmd.mac_offset = (uint16_t)(she_platform_data_buf(hdl->phdl, mac, SHE_MAC_SIZE, DATA_BUF_IS_INPUT | DATA_BUF_USE_SEC_MEM | DATA_BUF_SHORT_ADDR) & SEC_MEM_SHORT_ADDR_MASK);
        cmd.mac_length = mac_length;

        /* Send the message to Seco. */
        error = she_send_msg_and_get_resp(hdl->phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct she_cmd_verify_mac_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct she_cmd_verify_mac_rsp));
        if (error != 0) {
            break;
        }

        if ((hdl->cancel != 0u) || (GET_STATUS_CODE(rsp.rsp_code) != SAB_SUCCESS_STATUS)) {
            ret = she_seco_ind_to_she_err_t(rsp.rsp_code);
            *verification_status = SHE_MAC_VERIFICATION_FAILED;
            hdl->cancel = 0u;
            break;
        }

        /* Command success: Report the verification status. */
        *verification_status = (rsp.verification_status == 0u ? SHE_MAC_VERIFICATION_SUCCESS : SHE_MAC_VERIFICATION_FAILED);
        ret = ERC_NO_ERROR;
    } while (false);

    /* Force the status to fail in case of processing error. */
    if (ret != ERC_NO_ERROR) {
        *verification_status = SHE_MAC_VERIFICATION_FAILED;
    }

    return ret;
}

/* Generic function for encryption and decryption. */
static she_err_t she_cmd_cipher_one_go(struct she_hdl_s *hdl, uint8_t key_ext, uint8_t key_id, uint32_t data_length, uint8_t *iv, uint8_t *input, uint8_t *output, uint8_t flags, uint8_t algo)
{
    struct sab_cmd_cipher_one_go_msg cmd;
    struct sab_cmd_cipher_one_go_rsp rsp;
    int32_t error;
    uint64_t seco_iv_addr, seco_input_addr, seco_output_addr;
    uint16_t iv_size;
    she_err_t ret = ERC_GENERAL_ERROR;

    do {
        ret = she_open_cipher(hdl);
        if(ret != ERC_NO_ERROR) {
            break;
        }

        /* Build command message. */
        she_fill_cmd_msg_hdr(&cmd.hdr, SAB_CIPHER_ONE_GO_REQ, (uint32_t)sizeof(struct sab_cmd_cipher_one_go_msg));
        cmd.cipher_handle = hdl->cipher_handle;
        cmd.key_id = (uint16_t)key_ext | (uint16_t)key_id;
        cmd.algo = algo;
        cmd.flags = flags;

        if (algo == AHAB_CIPHER_ONE_GO_ALGO_ECB) {
            seco_iv_addr = 0;
            iv_size = 0;
        }
        else if (algo == AHAB_CIPHER_ONE_GO_ALGO_CBC) {
            seco_iv_addr = she_platform_data_buf(hdl->phdl, iv, SHE_AES_BLOCK_SIZE_128, DATA_BUF_IS_INPUT | DATA_BUF_USE_SEC_MEM);
            iv_size = SHE_AES_BLOCK_SIZE_128;
        } else {
            break;
        }

        seco_input_addr = she_platform_data_buf(hdl->phdl, input, data_length, DATA_BUF_IS_INPUT | DATA_BUF_USE_SEC_MEM);
        seco_output_addr = she_platform_data_buf(hdl->phdl, output, data_length, DATA_BUF_USE_SEC_MEM);

        /* Keep same layout in secure ram even for algos not using IV to simplify code here. */
        cmd.iv_address = (uint32_t)(seco_iv_addr & 0xFFFFFFFFu);
        cmd.input_address = (uint32_t)(seco_input_addr & 0xFFFFFFFFu);
        cmd.output_address = (uint32_t)(seco_output_addr & 0xFFFFFFFFu);
        cmd.data_length = data_length;
        cmd.iv_size = iv_size;
        cmd.crc = she_compute_msg_crc((uint32_t*)&cmd, (uint32_t)(sizeof(cmd) - sizeof(uint32_t)));


        /* Send the message to Seco. */
        error = she_send_msg_and_get_resp(hdl->phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_cmd_cipher_one_go_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_cmd_cipher_one_go_rsp));
        if (error != 0) {
            break;
        }

        if ((hdl->cancel != 0u) || (GET_STATUS_CODE(rsp.rsp_code) != SAB_SUCCESS_STATUS)) {
            ret = she_seco_ind_to_she_err_t(rsp.rsp_code);
            she_platform_memset(output, 0u, data_length);
            hdl->cancel = 0u;
            break;
        }

        ret = ERC_NO_ERROR;
    } while (false);

    if(she_close_cipher(hdl) != ERC_NO_ERROR) {
        ret = ERC_GENERAL_ERROR;
    }

    return ret;
}

/* CBC encrypt command. */
she_err_t she_cmd_enc_cbc(struct she_hdl_s *hdl, uint8_t key_ext, uint8_t key_id, uint32_t data_length, uint8_t *iv, uint8_t *plaintext, uint8_t *ciphertext)
{
    return she_cmd_cipher_one_go(hdl, key_ext, key_id, data_length, iv, plaintext, ciphertext, AHAB_CIPHER_ONE_GO_FLAGS_ENCRYPT, AHAB_CIPHER_ONE_GO_ALGO_CBC);
}

/* CBC decrypt command. */
she_err_t she_cmd_dec_cbc(struct she_hdl_s *hdl, uint8_t key_ext, uint8_t key_id, uint32_t data_length, uint8_t *iv, uint8_t *ciphertext, uint8_t *plaintext)
{
    return she_cmd_cipher_one_go(hdl, key_ext, key_id, data_length, iv, ciphertext, plaintext, AHAB_CIPHER_ONE_GO_FLAGS_DECRYPT, AHAB_CIPHER_ONE_GO_ALGO_CBC);
}

/* ECB encrypt command. */
she_err_t she_cmd_enc_ecb(struct she_hdl_s *hdl, uint8_t key_ext, uint8_t key_id, uint8_t *plaintext, uint8_t *ciphertext)
{
    return she_cmd_cipher_one_go(hdl, key_ext, key_id, SHE_AES_BLOCK_SIZE_128, NULL, plaintext, ciphertext, AHAB_CIPHER_ONE_GO_FLAGS_ENCRYPT, AHAB_CIPHER_ONE_GO_ALGO_ECB);
}

/* ECB decrypt command. */
she_err_t she_cmd_dec_ecb(struct she_hdl_s *hdl, uint8_t key_ext, uint8_t key_id, uint8_t *ciphertext, uint8_t *plaintext)
{
    return she_cmd_cipher_one_go(hdl, key_ext, key_id, SHE_AES_BLOCK_SIZE_128, NULL, ciphertext, plaintext, AHAB_CIPHER_ONE_GO_FLAGS_DECRYPT, AHAB_CIPHER_ONE_GO_ALGO_ECB);
}

/* Load key command processing. */
she_err_t she_cmd_load_key(struct she_hdl_s *hdl, uint8_t *m1, uint8_t *m2, uint8_t *m3, uint8_t *m4, uint8_t *m5)
{
    struct she_cmd_load_key_msg cmd;
    struct she_cmd_load_key_rsp rsp;
    int32_t error;
    she_err_t ret = ERC_GENERAL_ERROR;

    do {
        /* Build command message. */
        she_fill_cmd_msg_hdr(&cmd.hdr, AHAB_SHE_CMD_LOAD_KEY, (uint32_t)sizeof(struct she_cmd_load_key_msg));

        /* Send the message to Seco. */
        error = she_send_msg_and_get_resp(hdl->phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct she_cmd_load_key_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct she_cmd_load_key_rsp));
        if (error != 0) {
            break;
        }

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

she_err_t she_cmd_load_plain_key(struct she_hdl_s *hdl, uint8_t *key) 
{
    struct she_cmd_load_plain_key_msg cmd;
    struct she_cmd_load_plain_key_rsp rsp;
    int32_t error;
    she_err_t ret = ERC_GENERAL_ERROR;

    do {
        /* Build command message. */
        she_fill_cmd_msg_hdr(&cmd.hdr, AHAB_SHE_CMD_LOAD_PLAIN_KEY_REQ, (uint32_t)sizeof(struct she_cmd_load_plain_key_msg));
        she_platform_memcpy(cmd.key, key, SHE_KEY_SIZE);
        cmd.crc = she_compute_msg_crc((uint32_t*)&cmd, (uint32_t)(sizeof(cmd) - sizeof(uint32_t)));

        /* Send the message to Seco. */
        error = she_send_msg_and_get_resp(hdl->phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct she_cmd_load_plain_key_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct she_cmd_load_plain_key_rsp));
        if (error != 0) {
            break;
        }

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
    she_err_t ret = ERC_GENERAL_ERROR;

    return ret;
}

she_err_t she_cmd_init_rng(struct she_hdl_s *hdl) {
    struct sab_cmd_rng_open_msg cmd;
    struct sab_cmd_rng_open_rsp rsp;
    she_err_t ret = ERC_GENERAL_ERROR;
    int32_t error = 1;

    do {
        if (hdl->rng_handle != 0u) {
            break;
        }
        /* Send the keys store open command to Seco. */
        she_fill_cmd_msg_hdr(&cmd.hdr, SAB_RNG_OPEN_REQ, (uint32_t)sizeof(struct sab_cmd_rng_open_msg));
        cmd.session_handle = hdl->session_handle;
        cmd.input_address_ext = 0u;
        cmd.output_address_ext = 0u;
        cmd.flags = SHE_DEFAULT_RNG_OPEN_FLAGS;
        cmd.crc = she_compute_msg_crc((uint32_t*)&cmd, (uint32_t)(sizeof(cmd) - sizeof(uint32_t)));

        /* Send the message to Seco. */
        error = she_send_msg_and_get_resp(hdl->phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_cmd_rng_open_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_cmd_rng_open_rsp));
        if (error != 0) {
            break;
        }

        if ((hdl->cancel != 0u) || (GET_STATUS_CODE(rsp.rsp_code)!= SAB_SUCCESS_STATUS)) {
            ret = she_seco_ind_to_she_err_t(rsp.rsp_code);
            hdl->cancel = 0u;
            break;
        }

        hdl->rng_handle = rsp.rng_handle;
        /* Success. */
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
        if (hdl->rng_handle == 0u) {
            ret = ERC_SEQUENCE_ERROR;
            break;
        }
        /* Build command message. */
        she_fill_cmd_msg_hdr(&cmd.hdr, SAB_RNG_EXTEND_SEED, (uint32_t)sizeof(struct sab_cmd_extend_seed_msg));
        cmd.rng_handle = hdl->rng_handle;
        she_platform_memcpy((uint8_t *)cmd.entropy, entropy, SHE_ENTROPY_SIZE);
        cmd.crc = she_compute_msg_crc((uint32_t*)&cmd, (uint32_t)(sizeof(cmd) - sizeof(uint32_t)));

        /* Send the message to Seco. */
        error = she_send_msg_and_get_resp(hdl->phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_cmd_extend_seed_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_cmd_extend_seed_rsp));
        if (error != 0) {
            break;
        }

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
        if (hdl->rng_handle == 0u) {
            ret = ERC_SEQUENCE_ERROR;
            break;
        }

        /* Build command message. */
        she_fill_cmd_msg_hdr(&cmd.hdr, SAB_RNG_GET_RANDOM, (uint32_t)sizeof(struct sab_cmd_get_rnd_msg));
        seco_rnd_addr = she_platform_data_buf(hdl->phdl, rnd, SHE_RND_SIZE, DATA_BUF_USE_SEC_MEM);
        cmd.rng_handle = hdl->rng_handle;
        cmd.rnd_addr = (uint32_t)(seco_rnd_addr & 0xFFFFFFFFu);
        cmd.rnd_size = SHE_RND_SIZE;

        /* Send the message to Seco. */
        error = she_send_msg_and_get_resp(hdl->phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_cmd_get_rnd_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_cmd_get_rnd_rsp));
        if (error != 0) {
            break;
        }

        if ((hdl->cancel != 0u) || (GET_STATUS_CODE(rsp.rsp_code)!= SAB_SUCCESS_STATUS)) {
            ret = she_seco_ind_to_she_err_t(rsp.rsp_code);
            she_platform_memset(rnd, 0u, SHE_RND_SIZE);
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
        /* Build command message. */
        she_fill_cmd_msg_hdr(&cmd.hdr, AHAB_SHE_CMD_GET_STATUS_REQ, (uint32_t)sizeof(struct she_cmd_get_status_msg));

        /* Send the message to Seco. */
        error = she_send_msg_and_get_resp(hdl->phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct she_cmd_get_status_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct she_cmd_get_status_rsp));
        if (error != 0) {
            break;
        }

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
    uint64_t seco_challenge_addr, seco_mac_addr;

    do {
        /* Provide I/O buffers to Seco. */
        seco_mac_addr = she_platform_data_buf(hdl->phdl, mac, SHE_MAC_SIZE, DATA_BUF_USE_SEC_MEM);
        /* Build command message. */
        she_fill_cmd_msg_hdr(&cmd.hdr, AHAB_SHE_CMD_GET_ID_REQ, (uint32_t)sizeof(struct she_cmd_get_id_msg));
        she_platform_memcpy(cmd.challenge, challenge, SHE_CHALLENGE_SIZE);
        cmd.outputs_address_ext = (uint32_t)((seco_mac_addr >> 32u) & 0xFFFFFFFFu);
        cmd.mac_addr = (uint32_t)(seco_mac_addr & 0xFFFFFFFFu);
        cmd.crc = she_compute_msg_crc((uint32_t*)&cmd, (uint32_t)(sizeof(cmd) - sizeof(uint32_t)));

        /* Send the message to Seco. */
        error = she_send_msg_and_get_resp(hdl->phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct she_cmd_get_id_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct she_cmd_get_id_rsp));
        if (error != 0) {
            break;
        }

        if ((hdl->cancel != 0u)
            || (GET_STATUS_CODE(rsp.rsp_code)!= SAB_SUCCESS_STATUS)
            || (rsp.crc != she_compute_msg_crc((uint32_t*)&rsp, (uint32_t)(sizeof(rsp) - sizeof(uint32_t))))) {
            ret = she_seco_ind_to_she_err_t(rsp.rsp_code);
            *sreg = 0;
            she_platform_memset(id, 0u, SHE_ID_SIZE);
            hdl->cancel = 0u;
            break;
        }

        /* Success: copy sreg and id reported by SECO to output.*/
        *sreg = rsp.sreg;
        she_platform_memcpy(id, rsp.id, SHE_ID_SIZE);

        /* Success. */
        ret = ERC_NO_ERROR;
    } while (false);

    return ret;
}


she_err_t she_cmd_cancel(struct she_hdl_s *hdl) {
    she_err_t ret = ERC_GENERAL_ERROR;

    hdl->cancel = 1u;

    return ret;
}
