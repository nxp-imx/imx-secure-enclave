/*
 * Copyright 2019-2023 NXP
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

#include "internal/hsm_cipher.h"
#include "internal/hsm_rng.h"
#include "internal/hsm_get_info.h"
#include "internal/hsm_session.h"

#include "sab_msg_def.h"
#include "sab_messaging.h"
#include "sab_process_msg.h"
#include "she_api.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

struct she_hdl_s {
    struct plat_os_abs_hdl *phdl;
    uint32_t session_handle;
    uint32_t key_store_handle;
    uint32_t cipher_handle;
    uint32_t rng_handle;
    uint32_t utils_handle;
    uint32_t cancel;
    uint32_t last_rating;
    uint32_t mu_type;
};


/* Convert errors codes reported by PLATFORM to SHE error codes. */
static she_err_t she_plat_ind_to_she_err_t (uint32_t rsp_code)
{
    she_err_t err = ERC_GENERAL_ERROR;
    if (GET_STATUS_CODE(rsp_code) == SAB_SUCCESS_STATUS) {
        err = ERC_NO_ERROR;
    } else {
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
        case SAB_FATAL_FAILURE_RATING :
            err = ERC_FATAL_FAILURE;
            break;
        /* All other Secure-Enclave Platform's error codes. */
        default:
            err = ERC_GENERAL_ERROR;
            break;
        }
    }
    return err;
}



static she_err_t she_open_utils(struct she_hdl_s *hdl)
{
	struct sab_cmd_she_utils_open_msg cmd;
	struct sab_cmd_she_utils_open_rsp rsp;
	she_err_t ret = ERC_GENERAL_ERROR;
	int32_t error;
    do {

        if (hdl->utils_handle != 0u) {
            break;
        }
        /* Send the keys store open command to Secure-Enclave Platform. */
        plat_fill_cmd_msg_hdr(&cmd.hdr, SAB_SHE_UTILS_OPEN, (uint32_t)sizeof(struct sab_cmd_she_utils_open_msg), hdl->mu_type);
        cmd.input_address_ext = 0;
        cmd.output_address_ext = 0;
        cmd.key_store_handle = hdl->key_store_handle;

        error = plat_send_msg_and_get_resp(hdl->phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_cmd_she_utils_open_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_cmd_she_utils_open_rsp));

        if (error != 0) {
            break;
        }

        hdl->last_rating = rsp.rsp_code;
        if (GET_STATUS_CODE(rsp.rsp_code) != SAB_SUCCESS_STATUS) {
            ret = she_plat_ind_to_she_err_t(rsp.rsp_code);
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
	int32_t error;
    do {
        if (hdl->utils_handle == 0u){
            break;
        }
        /* Send the keys store open command to Secure-Enclave Platform. */
        plat_fill_cmd_msg_hdr(&cmd.hdr, SAB_SHE_UTILS_CLOSE, (uint32_t)sizeof(struct sab_cmd_she_utils_close_msg), hdl->mu_type);
        cmd.utils_handle = hdl->utils_handle;
        error = plat_send_msg_and_get_resp(hdl->phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_cmd_she_utils_close_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_cmd_she_utils_close_rsp));

        if (error != 0) {
            break;
        }

        hdl->last_rating = rsp.rsp_code;
        if (GET_STATUS_CODE(rsp.rsp_code) != SAB_SUCCESS_STATUS) {
            ret = she_plat_ind_to_she_err_t(rsp.rsp_code);
            break;
        }

        hdl->utils_handle = 0u;
        /* Success. */
        ret = ERC_NO_ERROR;
    } while(false);
    return ret;
}

/* Close a previously opened SHE session. */
void she_close_session(struct she_hdl_s *hdl)
{
	int32_t error;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

    if (hdl != NULL) {
        if (hdl->phdl != NULL) {
            (void) she_close_utils(hdl);
            if (hdl->cipher_handle != 0u) {

                error = process_sab_msg(hdl->phdl,
                                        hdl->mu_type,
                                        SAB_CIPHER_CLOSE_REQ,
                                        MT_SAB_CIPHER,
                                        (uint32_t)hdl->cipher_handle,
                                        NULL, &rsp_code);
		if (rsp_code || (error != SAB_SUCCESS_STATUS))
			printf("SAB FW Error[0x%x]: SAB_CIPHER_CLOSE_REQ.\n",
								rsp_code);
            }
            if (hdl->rng_handle != 0u) {
		error = process_sab_msg(hdl->phdl,
					hdl->mu_type,
					SAB_RNG_CLOSE_REQ,
					MT_SAB_RNG,
					(uint32_t)hdl->rng_handle,
					NULL, &rsp_code);
		if (rsp_code || (error != SAB_SUCCESS_STATUS))
			printf("SAB FW Error[0x%x]: SAB_RNG_CLOSE_REQ.\n",
								rsp_code);
            }
            if (hdl->key_store_handle != 0u) {
                (void)sab_close_key_store(hdl->phdl, hdl->key_store_handle, hdl->mu_type);
                hdl->key_store_handle = 0u;
            }
            if (hdl -> session_handle != 0u) {
		error = process_sab_msg(hdl->phdl,
					hdl->mu_type,
					SAB_SESSION_CLOSE_REQ,
					MT_SAB_SESSION,
					hdl->session_handle,
					NULL, &rsp_code);
		if (error != SAB_SUCCESS_STATUS)
			printf("SAB FW Error[0x%x]: SAB_SESSION_CLOSE_REQ.\n", rsp_code);
                hdl -> session_handle = 0u;
            }
            plat_os_abs_close_session(hdl->phdl);
            hdl->phdl = NULL;
        }
        plat_os_abs_free(hdl);
    }
}

#define MIN_MAC_LEN_NOT_SET  (0u)
#define MIN_MAC_LEN_SET      (1u)
static uint32_t she_storage_create_generic(uint32_t key_storage_identifier, uint32_t authentication_nonce, uint16_t max_updates_number, uint8_t min_mac_len_setting, uint8_t min_mac_length, uint8_t *signed_message, uint32_t msg_len) {
	struct she_hdl_s *hdl = NULL;
	uint32_t ret = SHE_STORAGE_CREATE_FAIL;
	uint32_t err;
	struct plat_mu_params mu_params = {0};
	open_session_args_t args;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;
	uint8_t flags = KEY_STORE_OPEN_FLAGS_CREATE | KEY_STORE_OPEN_FLAGS_SHE;
    do {
        /* allocate the handle (free when closing the session). */
        hdl = (struct she_hdl_s *)plat_os_abs_malloc((uint32_t)sizeof(struct she_hdl_s));
        if (hdl == NULL) {
            break;
        }
        plat_os_abs_memset((uint8_t *)hdl, 0u, (uint32_t)sizeof(struct she_hdl_s));

        /* Open the SHE session on the SHE kernel driver */
        hdl->mu_type = MU_CHANNEL_PLAT_SHE;
        hdl->phdl = plat_os_abs_open_mu_channel(hdl->mu_type, &mu_params);
        if (hdl->phdl == NULL) {
            break;
        }

        /* Send the signed message to platform if provided here. */
        if (signed_message != NULL) {
            (void)plat_os_abs_send_signed_message(hdl->phdl, signed_message, msg_len);
        }

		/* Open the SHE session on platform side */
		args.mu_id = mu_params.mu_id;
		args.interrupt_idx = mu_params.interrupt_idx;
		args.tz = mu_params.tz;
		args.did = mu_params.did;
		args.session_priority = 0U;
		args.operating_mode = 0U;

		err = process_sab_msg(hdl->phdl,
				      hdl->mu_type,
				      SAB_SESSION_OPEN_REQ,
				      MT_SAB_SESSION,
				      hdl->session_handle,
				      &args, &rsp_code);
		ret = rsp_code;
		if (err != SAB_SUCCESS_STATUS) {
			printf("SAB FW Error[0x%x]: SAB_SESSION_OPEN_REQ.\n", rsp_code);
			hdl->session_handle = 0u;
			break;
		}

		hdl->session_handle = args.session_hdl;

        if(min_mac_len_setting == MIN_MAC_LEN_SET) {
            flags |= KEY_STORE_OPEN_FLAGS_SET_MAC_LEN;
        }

        /* Create the SHE keystore */
        err = sab_open_key_store_command(hdl->phdl,
                                         hdl->session_handle,
                                         &hdl->key_store_handle,
                                         hdl->mu_type,
                                         key_storage_identifier,
                                         authentication_nonce,
                                         max_updates_number,
                                         flags,
                                         min_mac_length);

        /* Interpret Secure-Enclave Platform status code*/
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

uint32_t she_storage_create(uint32_t key_storage_identifier, uint32_t authentication_nonce, uint16_t max_updates_number, uint8_t *signed_message, uint32_t msg_len)
{
    return she_storage_create_generic(key_storage_identifier, authentication_nonce, max_updates_number, MIN_MAC_LEN_NOT_SET, MIN_MAC_LEN_NOT_SET, signed_message, msg_len);
}

uint32_t she_storage_create_ext(uint32_t key_storage_identifier, uint32_t authentication_nonce, uint16_t max_updates_number, uint8_t min_mac_length, uint8_t *signed_message, uint32_t msg_len)
{
    return she_storage_create_generic(key_storage_identifier, authentication_nonce, max_updates_number, MIN_MAC_LEN_SET, min_mac_length, signed_message, msg_len);
}


/* Open a SHE user session and return a pointer to the session handle. */
struct she_hdl_s *she_open_session(uint32_t key_storage_identifier, uint32_t authentication_nonce, void (*async_cb)(void *priv, she_err_t err), void *priv)
{
	struct she_hdl_s *hdl = NULL;
	uint32_t err = SAB_FAILURE_STATUS;
	struct plat_mu_params mu_params = {0};
	open_svc_cipher_args_t op_args;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;
	open_session_args_t args;

    do {
        if((async_cb != NULL) || (priv != NULL)) {
            /* not supported yet. */
            break;
        }
        /* allocate the handle (free when closing the session). */
        hdl = (struct she_hdl_s *)plat_os_abs_malloc((uint32_t)sizeof(struct she_hdl_s));
        if (hdl == NULL) {
            break;
        }
        plat_os_abs_memset((uint8_t *)hdl, 0u, (uint32_t)sizeof(struct she_hdl_s));

        /* Open the SHE session on the MU */
        hdl->mu_type = MU_CHANNEL_PLAT_SHE;
        hdl->phdl = plat_os_abs_open_mu_channel(hdl->mu_type, &mu_params);
        if (hdl->phdl == NULL) {
            break;
        }

        /* Open the SHE session on Secure-Enclave Platform's side */
		args.mu_id = mu_params.mu_id;
		args.interrupt_idx = mu_params.interrupt_idx;
		args.tz = mu_params.tz;
		args.did = mu_params.did;
		args.session_priority = 0U;
		args.operating_mode = 0U;

		err = process_sab_msg(hdl->phdl,
				      hdl->mu_type,
				      SAB_SESSION_OPEN_REQ,
				      MT_SAB_SESSION,
				      hdl->session_handle,
				      &args, &rsp_code);
		if (err != SAB_SUCCESS_STATUS) {
			printf("SAB FW Error[0x%x]: SAB_SESSION_OPEN_REQ.\n", rsp_code);
			hdl->session_handle = 0u;
			break;
		}

		hdl->session_handle = args.session_hdl;

        /* Get a SECURE RAM partition to be used as shared buffer */
        err = sab_get_shared_buffer(hdl->phdl, hdl->session_handle, hdl->mu_type);
        if (err != SAB_SUCCESS_STATUS) {
            break;
        }
        /* Get the access to the SHE keystore */
        err = sab_open_key_store_command(hdl->phdl,
                                         hdl->session_handle,
                                         &hdl->key_store_handle,
                                         hdl->mu_type,
                                         key_storage_identifier,
                                         authentication_nonce,
                                         0u,
                                         KEY_STORE_OPEN_FLAGS_SHE,
                                         0);
        if (err != SAB_SUCCESS_STATUS) {
            hdl->key_store_handle = 0u;
            break;
        }

        /* open SHE utils service. */
        if (she_open_utils(hdl) != ERC_NO_ERROR) {
            break;
        }

	op_args.flags = CIPHER_OPEN_FLAGS_DEFAULT;
        /* open cipher service. */
        err = process_sab_msg(hdl->phdl,
                              hdl->mu_type,
                              SAB_CIPHER_OPEN_REQ,
                              MT_SAB_CIPHER,
                              (uint32_t)hdl->key_store_handle,
                              &op_args, &rsp_code);
        if (rsp_code || (err != SAB_SUCCESS_STATUS)) {
	    printf("SAB FW Error[0x%x]: SAB_CIPHER_OPEN_REQ.\n",
							rsp_code);
            hdl->cipher_handle = 0u;
            break;
        }
        hdl->cipher_handle = op_args.cipher_hdl;
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
        plat_fill_cmd_msg_hdr(&cmd.hdr, SAB_FAST_MAC_REQ, (uint32_t)sizeof(struct sab_she_fast_mac_msg), hdl->mu_type);
        cmd.she_utils_handle = hdl->utils_handle;
        cmd.key_id = (uint16_t)key_ext | (uint16_t)key_id;
        cmd.data_length = message_length;
        /* the MAC data is stored right after the input data */
        if (message_length == 0u) {
            cmd.data_offset = (uint16_t)(plat_os_abs_data_buf(hdl->phdl, mac, SHE_MAC_SIZE, DATA_BUF_USE_SEC_MEM | DATA_BUF_SHORT_ADDR) & SEC_MEM_SHORT_ADDR_MASK);
        } else {
            cmd.data_offset = (uint16_t)(plat_os_abs_data_buf(hdl->phdl, message, message_length, DATA_BUF_IS_INPUT | DATA_BUF_USE_SEC_MEM | DATA_BUF_SHORT_ADDR) & SEC_MEM_SHORT_ADDR_MASK);
            (void)(plat_os_abs_data_buf(hdl->phdl, mac, SHE_MAC_SIZE, DATA_BUF_USE_SEC_MEM | DATA_BUF_SHORT_ADDR) & SEC_MEM_SHORT_ADDR_MASK);
        }
        cmd.mac_length = 0u;
        cmd.flags = 0u;

        /* Send the message to Secure-Enclave Platform. */
        error = plat_send_msg_and_get_resp(hdl->phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_she_fast_mac_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_she_fast_mac_rsp));
        if (error != 0) {
            break;
        }

        hdl->last_rating = rsp.rsp_code;
        if ((hdl->cancel != 0u) || (GET_STATUS_CODE(rsp.rsp_code) != SAB_SUCCESS_STATUS)) {
            ret = she_plat_ind_to_she_err_t(rsp.rsp_code);
            plat_os_abs_memset(mac, 0u, SHE_MAC_SIZE);
            hdl->cancel = 0u;
            break;
        }

        /* Success. */
        ret = ERC_NO_ERROR;
    } while (false);

    return ret;
}

#define MAC_BYTES_LENGTH    (0)
#define MAC_BITS_LENGTH     (1)
/* MAC verify command processing. */
static she_err_t she_cmd_verify_mac_generic(struct she_hdl_s *hdl, uint8_t key_ext, uint8_t key_id, uint16_t message_length, uint8_t *message, uint8_t *mac, uint8_t mac_length, uint8_t mac_length_encoding, uint8_t *verification_status)
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
        plat_fill_cmd_msg_hdr(&cmd.hdr, SAB_FAST_MAC_REQ, (uint32_t)sizeof(struct sab_she_fast_mac_msg), hdl->mu_type);
        cmd.she_utils_handle = hdl->utils_handle;
        cmd.key_id = (uint16_t)key_ext | (uint16_t)key_id;
        cmd.data_length = message_length;
        /* the MAC data is stored right after the input data */
        if (message_length == 0u) {
            cmd.data_offset = (uint16_t)(plat_os_abs_data_buf(hdl->phdl, mac, SHE_MAC_SIZE, DATA_BUF_IS_INPUT |DATA_BUF_USE_SEC_MEM | DATA_BUF_SHORT_ADDR) & SEC_MEM_SHORT_ADDR_MASK);
        } else {
            cmd.data_offset = (uint16_t)(plat_os_abs_data_buf(hdl->phdl, message, message_length, DATA_BUF_IS_INPUT | DATA_BUF_USE_SEC_MEM | DATA_BUF_SHORT_ADDR) & SEC_MEM_SHORT_ADDR_MASK);
            (void)(plat_os_abs_data_buf(hdl->phdl, mac, SHE_MAC_SIZE, DATA_BUF_IS_INPUT | DATA_BUF_USE_SEC_MEM | DATA_BUF_SHORT_ADDR) & SEC_MEM_SHORT_ADDR_MASK);
        }
        cmd.mac_length = mac_length;
        cmd.flags = SAB_SHE_FAST_MAC_FLAGS_VERIFICATION;
        if (mac_length_encoding == MAC_BITS_LENGTH) {
            cmd.flags |= SAB_SHE_FAST_MAC_FLAGS_VERIF_BIT_LEN;
        }

        /* Send the message to Secure-Enclave Platform. */
        error = plat_send_msg_and_get_resp(hdl->phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_she_fast_mac_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_she_fast_mac_rsp));
        if (error != 0) {
            break;
        }

        hdl->last_rating = rsp.rsp_code;
        if ((hdl->cancel != 0u) || (GET_STATUS_CODE(rsp.rsp_code) != SAB_SUCCESS_STATUS)) {
            ret = she_plat_ind_to_she_err_t(rsp.rsp_code);
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

she_err_t she_cmd_verify_mac(struct she_hdl_s *hdl, uint8_t key_ext, uint8_t key_id, uint16_t message_length, uint8_t *message, uint8_t *mac, uint8_t mac_length, uint8_t *verification_status) {
    return she_cmd_verify_mac_generic(hdl, key_ext, key_id, message_length, message, mac, mac_length, MAC_BYTES_LENGTH, verification_status);
}

she_err_t she_cmd_verify_mac_bit_ext(struct she_hdl_s *hdl, uint8_t key_ext, uint8_t key_id, uint16_t message_length, uint8_t *message, uint8_t *mac, uint8_t mac_bit_length, uint8_t *verification_status) {
    return she_cmd_verify_mac_generic(hdl, key_ext, key_id, message_length, message, mac, mac_bit_length, MAC_BITS_LENGTH, verification_status);
}

/* CBC encrypt command. */
she_err_t she_cmd_enc_cbc(struct she_hdl_s *hdl, uint8_t key_ext, uint8_t key_id, uint32_t data_length, uint8_t *iv, uint8_t *plaintext, uint8_t *ciphertext)
{
	uint32_t sab_error, rsp_code = SAB_NO_MESSAGE_RATING;
	she_err_t ret;
    op_cipher_one_go_args_t op_args;

    op_args.key_identifier = (uint32_t)key_ext | (uint32_t)key_id;
    op_args.iv = iv;
    op_args.iv_size = SHE_AES_BLOCK_SIZE_128;
    op_args.cipher_algo = AHAB_CIPHER_ONE_GO_ALGO_CBC;
    op_args.flags = AHAB_CIPHER_ONE_GO_FLAGS_ENCRYPT;
    op_args.input = plaintext;
    op_args.output = ciphertext;
    op_args.input_size = data_length;
    op_args.output_size = data_length;

    sab_error = process_sab_msg(hdl->phdl,
                                hdl->mu_type,
                                SAB_CIPHER_ONE_GO_REQ,
                                MT_SAB_CIPHER,
                                (uint32_t)hdl->cipher_handle,
                                &op_args, &rsp_code);

    hdl->last_rating = sab_error;

    if (rsp_code
        || (sab_error != SAB_SUCCESS_STATUS)
        || (hdl->cancel != 0u)) {
        printf("SAB FW Error[0x%x]: SAB_CIPHER_ONE_GO_REQ.\n", rsp_code);

        plat_os_abs_memset(ciphertext, 0u, data_length);
        hdl->cancel = 0u;
    }

    ret = she_plat_ind_to_she_err_t(sab_error);

    return ret;
}

/* CBC decrypt command. */
she_err_t she_cmd_dec_cbc(struct she_hdl_s *hdl, uint8_t key_ext, uint8_t key_id, uint32_t data_length, uint8_t *iv, uint8_t *ciphertext, uint8_t *plaintext)
{
	uint32_t sab_error, rsp_code = SAB_NO_MESSAGE_RATING;
	she_err_t ret;
	op_cipher_one_go_args_t op_args;

    op_args.key_identifier = (uint32_t)key_ext | (uint32_t)key_id;
    op_args.iv = iv;
    op_args.iv_size = SHE_AES_BLOCK_SIZE_128;
    op_args.cipher_algo = AHAB_CIPHER_ONE_GO_ALGO_CBC;
    op_args.flags = AHAB_CIPHER_ONE_GO_FLAGS_DECRYPT;
    op_args.input = ciphertext;
    op_args.output = plaintext;
    op_args.input_size = data_length;
    op_args.output_size = data_length;

    sab_error = process_sab_msg(hdl->phdl,
                            hdl->mu_type,
                            SAB_CIPHER_ONE_GO_REQ,
                            MT_SAB_CIPHER,
                            (uint32_t)hdl->cipher_handle,
                            &op_args, &rsp_code);

    hdl->last_rating = sab_error;

    if (rsp_code
        || (sab_error != SAB_SUCCESS_STATUS)
	|| (hdl->cancel != 0u)) {
        printf("SAB FW Error[0x%x]: SAB_CIPHER_ONE_GO_REQ.\n", rsp_code);

        plat_os_abs_memset(plaintext, 0u, data_length);
        hdl->cancel = 0u;
    }

    ret = she_plat_ind_to_she_err_t(sab_error);

    return ret;
}

/* ECB encrypt command. */
she_err_t she_cmd_enc_ecb(struct she_hdl_s *hdl, uint8_t key_ext, uint8_t key_id, uint8_t *plaintext, uint8_t *ciphertext)
{
	uint32_t sab_error;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;
	she_err_t ret;
	op_cipher_one_go_args_t op_args;

    op_args.key_identifier = (uint32_t)key_ext | (uint32_t)key_id;
    op_args.iv = NULL;
    op_args.iv_size = 0u;
    op_args.cipher_algo = AHAB_CIPHER_ONE_GO_ALGO_ECB;
    op_args.flags = AHAB_CIPHER_ONE_GO_FLAGS_ENCRYPT;
    op_args.input = plaintext;
    op_args.output = ciphertext;
    op_args.input_size = SHE_AES_BLOCK_SIZE_128;
    op_args.output_size = SHE_AES_BLOCK_SIZE_128;

    sab_error = process_sab_msg(hdl->phdl,
                            hdl->mu_type,
                            SAB_CIPHER_ONE_GO_REQ,
                            MT_SAB_CIPHER,
                            (uint32_t)hdl->cipher_handle,
                            &op_args, &rsp_code);

    hdl->last_rating = sab_error;

    if ((hdl->cancel != 0u) || rsp_code || (sab_error != SAB_SUCCESS_STATUS)) {
        printf("SAB FW Error[0x%x]: SAB_CIPHER_ONE_GO_REQ.\n", rsp_code);
        plat_os_abs_memset(ciphertext, 0u, SHE_AES_BLOCK_SIZE_128);
        hdl->cancel = 0u;
    }

    ret = she_plat_ind_to_she_err_t(sab_error);

    return ret;
}

/* ECB decrypt command. */
she_err_t she_cmd_dec_ecb(struct she_hdl_s *hdl, uint8_t key_ext, uint8_t key_id, uint8_t *ciphertext, uint8_t *plaintext)
{
	uint32_t sab_error;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;
	she_err_t ret;
	op_cipher_one_go_args_t op_args;

    op_args.key_identifier = (uint32_t)key_ext | (uint32_t)key_id;
    op_args.iv = NULL;
    op_args.iv_size = 0u;
    op_args.cipher_algo = AHAB_CIPHER_ONE_GO_ALGO_ECB;
    op_args.flags = AHAB_CIPHER_ONE_GO_FLAGS_DECRYPT;
    op_args.input = ciphertext;
    op_args.output = plaintext;
    op_args.input_size = SHE_AES_BLOCK_SIZE_128;
    op_args.output_size = SHE_AES_BLOCK_SIZE_128;

    sab_error = process_sab_msg(hdl->phdl,
                            hdl->mu_type,
                            SAB_CIPHER_ONE_GO_REQ,
                            MT_SAB_CIPHER,
                            (uint32_t)hdl->cipher_handle,
                            &op_args, &rsp_code);

    hdl->last_rating = sab_error;

    if ((hdl->cancel != 0u) || rsp_code || (sab_error != SAB_SUCCESS_STATUS)) {
        printf("SAB FW Error[0x%x]: SAB_CIPHER_ONE_GO_REQ.\n", rsp_code);
        plat_os_abs_memset(plaintext, 0u, SHE_AES_BLOCK_SIZE_128);
        hdl->cancel = 0u;
    }

    ret = she_plat_ind_to_she_err_t(sab_error);
    return ret;
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
        plat_fill_cmd_msg_hdr(&cmd.hdr, SAB_SHE_KEY_UPDATE, (uint32_t)sizeof(struct sab_she_key_update_msg), hdl->mu_type);
        cmd.utils_handle = hdl->utils_handle;
        cmd.key_id = (uint32_t)key_ext | (uint32_t)key_id;
        plat_os_abs_memcpy((uint8_t *)cmd.m1, m1, SHE_KEY_SIZE);
        plat_os_abs_memcpy((uint8_t *)cmd.m2, m2, 2u * SHE_KEY_SIZE);
        plat_os_abs_memcpy((uint8_t *)cmd.m3, m3, SHE_KEY_SIZE);
        cmd.crc = plat_compute_msg_crc((uint32_t*)&cmd, (uint32_t)(sizeof(cmd) - sizeof(uint32_t)));

        /* Send the message to Secure-Enclave Platform. */
        error = plat_send_msg_and_get_resp(hdl->phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_she_key_update_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_she_key_update_rsp));
        if (error != 0) {
            break;
        }

        hdl->last_rating = rsp.rsp_code;
        if ((hdl->cancel != 0u)
            || (GET_STATUS_CODE(rsp.rsp_code)!= SAB_SUCCESS_STATUS)
            || (rsp.crc != plat_compute_msg_crc((uint32_t*)&rsp, (uint32_t)(sizeof(rsp) - sizeof(uint32_t))))) {
            ret = she_plat_ind_to_she_err_t(rsp.rsp_code);
            plat_os_abs_memset(m4, 0u, 2u * SHE_KEY_SIZE);
            plat_os_abs_memset(m5, 0u, SHE_KEY_SIZE);
            hdl->cancel = 0u;
            break;
        }

        /* Success: copy m4 and m5 reported by Secure-Enclave Platform, to output.*/
        plat_os_abs_memcpy(m4, (uint8_t *)rsp.m4, 2u * SHE_KEY_SIZE);
        plat_os_abs_memcpy(m5, (uint8_t *)rsp.m5, SHE_KEY_SIZE);

        /* Success. */
        ret = ERC_NO_ERROR;
    } while (false);

    return ret;
}

/* Load key ext command processing. */
she_err_t she_cmd_load_key_ext(struct she_hdl_s *hdl, uint8_t key_ext, uint8_t key_id, uint8_t *m1, uint8_t *m2, uint8_t *m3, uint8_t *m4, uint8_t *m5, she_cmd_load_key_ext_flags_t flags)
{
    struct sab_she_key_update_ext_msg cmd;
    struct sab_she_key_update_ext_rsp rsp;
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
        plat_fill_cmd_msg_hdr(&cmd.hdr, SAB_SHE_KEY_UPDATE_EXT, (uint32_t)sizeof(struct sab_she_key_update_ext_msg), hdl->mu_type);
        cmd.utils_handle = hdl->utils_handle;
        cmd.key_id = (uint32_t)key_ext | (uint32_t)key_id;
        plat_os_abs_memcpy((uint8_t *)cmd.m1, m1, SHE_KEY_SIZE);
        plat_os_abs_memcpy((uint8_t *)cmd.m2, m2, 2u * SHE_KEY_SIZE);
        plat_os_abs_memcpy((uint8_t *)cmd.m3, m3, SHE_KEY_SIZE);
        cmd.flags = flags;
        cmd.pad[0] = 0u;
        cmd.pad[1] = 0u;
        cmd.pad[2] = 0u;
        cmd.crc = 0u;
        cmd.crc = plat_compute_msg_crc((uint32_t*)&cmd, (uint32_t)(sizeof(cmd) - sizeof(uint32_t)));

        /* Send the message to Secure-Enclave Platform. */
        error = plat_send_msg_and_get_resp(hdl->phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_she_key_update_ext_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_she_key_update_ext_rsp));
        if (error != 0) {
            break;
        }

        hdl->last_rating = rsp.rsp_code;
        if ((hdl->cancel != 0u)
            || (GET_STATUS_CODE(rsp.rsp_code)!= SAB_SUCCESS_STATUS)
            || (rsp.crc != plat_compute_msg_crc((uint32_t*)&rsp, (uint32_t)(sizeof(rsp) - sizeof(uint32_t))))) {
            ret = she_plat_ind_to_she_err_t(rsp.rsp_code);
            plat_os_abs_memset(m4, 0u, 2u * SHE_KEY_SIZE);
            plat_os_abs_memset(m5, 0u, SHE_KEY_SIZE);
            hdl->cancel = 0u;
            break;
        }

        /* Success: copy m4 and m5 reported by Secure-Enclave Platform, to output.*/
        plat_os_abs_memcpy(m4, (uint8_t *)rsp.m4, 2u * SHE_KEY_SIZE);
        plat_os_abs_memcpy(m5, (uint8_t *)rsp.m5, SHE_KEY_SIZE);

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
        plat_fill_cmd_msg_hdr(&cmd.hdr, SAB_SHE_PLAIN_KEY_UPDATE, (uint32_t)sizeof(struct she_cmd_load_plain_key_msg), hdl->mu_type);

        plat_os_abs_memcpy(cmd.key, key, SHE_KEY_SIZE);
        cmd.she_utils_handle = hdl->utils_handle;
        cmd.crc = plat_compute_msg_crc((uint32_t*)&cmd, (uint32_t)(sizeof(cmd) - sizeof(uint32_t)));

        /* Send the message to Secure-Enclave Platform. */
        error = plat_send_msg_and_get_resp(hdl->phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct she_cmd_load_plain_key_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct she_cmd_load_plain_key_rsp));
        if (error != 0) {
            break;
        }

        hdl->last_rating = rsp.rsp_code;
        if ((hdl->cancel != 0u) || (GET_STATUS_CODE(rsp.rsp_code)!= SAB_SUCCESS_STATUS)) {
            ret = she_plat_ind_to_she_err_t(rsp.rsp_code);
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
        plat_fill_cmd_msg_hdr(&cmd.hdr, SAB_SHE_PLAIN_KEY_EXPORT, (uint32_t)sizeof(struct sab_she_plain_key_export_msg), hdl->mu_type);
        cmd.utils_handle = hdl->utils_handle;

        /* Send the message to Secure-Enclave Platform. */
        error = plat_send_msg_and_get_resp(hdl->phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_she_plain_key_export_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_she_plain_key_export_rsp));
        if (error != 0) {
            break;
        }

        hdl->last_rating = rsp.rsp_code;
        if ((hdl->cancel != 0u)
            || (GET_STATUS_CODE(rsp.rsp_code)!= SAB_SUCCESS_STATUS)
            || (rsp.crc != plat_compute_msg_crc((uint32_t*)&rsp, (uint32_t)(sizeof(rsp) - sizeof(uint32_t))))) {
            ret = she_plat_ind_to_she_err_t(rsp.rsp_code);
            plat_os_abs_memset(m1, 0u, SHE_KEY_SIZE);
            plat_os_abs_memset(m2, 0u, 2u * SHE_KEY_SIZE);
            plat_os_abs_memset(m3, 0u, SHE_KEY_SIZE);
            plat_os_abs_memset(m4, 0u, 2u * SHE_KEY_SIZE);
            plat_os_abs_memset(m5, 0u, SHE_KEY_SIZE);
            hdl->cancel = 0u;
            break;
        }

        /* Success: copy m1..m5 reported by Secure-Enclave Platform, to output.*/
        plat_os_abs_memcpy(m1, (uint8_t *)rsp.m1, SHE_KEY_SIZE);
        plat_os_abs_memcpy(m2, (uint8_t *)rsp.m2, 2u * SHE_KEY_SIZE);
        plat_os_abs_memcpy(m3, (uint8_t *)rsp.m3, SHE_KEY_SIZE);
        plat_os_abs_memcpy(m4, (uint8_t *)rsp.m4, 2u * SHE_KEY_SIZE);
        plat_os_abs_memcpy(m5, (uint8_t *)rsp.m5, SHE_KEY_SIZE);

        /* Success. */
        ret = ERC_NO_ERROR;
    } while (false);

    return ret;
}

#ifndef PSA_COMPLIANT
she_err_t she_cmd_init_rng(struct she_hdl_s *hdl) {
    uint32_t plat_rsp_code;
    int32_t error;
    she_err_t ret = ERC_GENERAL_ERROR;
    open_svc_rng_args_t args;

    do {
        if (hdl == NULL) {
            break;
        }
        /* Start the RNG at system level. */
        plat_os_abs_start_system_rng(hdl->phdl);

#ifndef PSA_COMPLIANT
	args.flags = 0;
#endif
        /* Then send the command to Secure-Enclave Platform, so it can perform its own RNG inits. */
	error = process_sab_msg(hdl->phdl,
				hdl->mu_type,
				SAB_RNG_OPEN_REQ,
				MT_SAB_RNG,
				(uint32_t)hdl->session_handle,
				&args, &plat_rsp_code);
	if ((plat_rsp_code != SAB_SUCCESS_STATUS) || (error != SAB_SUCCESS_STATUS)) {
		printf("SAB FW Error[0x%x]: SAB_RNG_CLOSE_REQ.\n",
							plat_rsp_code);
		break;
	}
	hdl->rng_handle = args.rng_hdl;

        if ((hdl->cancel != 0u) || (GET_STATUS_CODE(plat_rsp_code)!= SAB_SUCCESS_STATUS)) {
            hdl->rng_handle = 0u;
            ret = she_plat_ind_to_she_err_t(plat_rsp_code);
            hdl->cancel = 0u;
            break;
        }

        ret = ERC_NO_ERROR;
    } while(false);
    return ret;
}
#endif


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
            ret = ERC_RNG_SEED;
            break;
        }
        /* Build command message. */
        plat_fill_cmd_msg_hdr(&cmd.hdr, SAB_RNG_EXTEND_SEED, (uint32_t)sizeof(struct sab_cmd_extend_seed_msg), hdl->mu_type);
        cmd.rng_handle = hdl->rng_handle;
        plat_os_abs_memcpy((uint8_t *)cmd.entropy, entropy, SHE_ENTROPY_SIZE);
        cmd.crc = plat_compute_msg_crc((uint32_t*)&cmd, (uint32_t)(sizeof(cmd) - sizeof(uint32_t)));

        /* Send the message to Secure-Enclave Platform. */
        error = plat_send_msg_and_get_resp(hdl->phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_cmd_extend_seed_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_cmd_extend_seed_rsp));
        if (error != 0) {
            break;
        }

        hdl->last_rating = rsp.rsp_code;
        if ((hdl->cancel != 0u) || (GET_STATUS_CODE(rsp.rsp_code)!= SAB_SUCCESS_STATUS)) {
            ret = she_plat_ind_to_she_err_t(rsp.rsp_code);
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
	int32_t error;
	op_get_random_args_t args = {0};
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

    do {
        if ((hdl == NULL) || (rnd == NULL)) {
            break;
        }
        if (hdl->rng_handle == 0u) {
            ret = ERC_SEQUENCE_ERROR;
            break;
        }

	args.random_size = SHE_RND_SIZE;
	args.output = rnd;

	error = process_sab_msg(hdl->phdl,
				hdl->mu_type,
				SAB_RNG_GET_RANDOM,
				MT_SAB_RNG,
				(uint32_t)hdl->rng_handle,
				&args, &rsp_code);

	ret = sab_rating_to_hsm_err(error);

	if (ret != ERC_NO_ERROR) {
		printf("HSM Error: SAB_RNG_GET_RANDOM [0x%x].\n", ret);
		break;
	}

	ret = sab_rating_to_hsm_err(rsp_code);

	if (ret != ERC_NO_ERROR) {
		printf("HSM RSP Error: SAB_RNG_GET_RANDOM [0x%x].\n", ret);
	}

        hdl->last_rating = rsp_code;
        if ((hdl->cancel != 0u) || (GET_STATUS_CODE(rsp_code)!= SAB_SUCCESS_STATUS)) {
            ret = she_plat_ind_to_she_err_t(rsp_code);
            plat_os_abs_memset(rnd, 0u, SHE_RND_SIZE);
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
        plat_fill_cmd_msg_hdr(&cmd.hdr, SAB_SHE_GET_STATUS, (uint32_t)sizeof(struct she_cmd_get_status_msg), hdl->mu_type);
        cmd.she_utils_handle = hdl->utils_handle;

        /* Send the message to Secure-Enclave Platform. */
        error = plat_send_msg_and_get_resp(hdl->phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct she_cmd_get_status_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct she_cmd_get_status_rsp));
        if (error != 0) {
            break;
        }

        hdl->last_rating = rsp.rsp_code;
        if ((hdl->cancel != 0u) || (GET_STATUS_CODE(rsp.rsp_code)!= SAB_SUCCESS_STATUS)) {
            ret = she_plat_ind_to_she_err_t(rsp.rsp_code);
            *sreg = 0;
            hdl->cancel = 0u;
            break;
        }

        /* Success: write sreg reported by Secure-Enclave Platform, to output.*/
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
        plat_fill_cmd_msg_hdr(&cmd.hdr, SAB_SHE_GET_ID, (uint32_t)sizeof(struct she_cmd_get_id_msg), hdl->mu_type);
        plat_os_abs_memcpy(cmd.challenge, challenge, SHE_CHALLENGE_SIZE);
        cmd.she_utils_handle = hdl->utils_handle;
        cmd.crc = plat_compute_msg_crc((uint32_t*)&cmd, (uint32_t)(sizeof(cmd) - sizeof(uint32_t)));

        /* Send the message to Secure-Enclave Platform. */
        error = plat_send_msg_and_get_resp(hdl->phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct she_cmd_get_id_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct she_cmd_get_id_rsp));
        if (error != 0) {
            break;
        }

        hdl->last_rating = rsp.rsp_code;
        if ((hdl->cancel != 0u)
            || (GET_STATUS_CODE(rsp.rsp_code)!= SAB_SUCCESS_STATUS)
            || (rsp.crc != plat_compute_msg_crc((uint32_t*)&rsp, (uint32_t)(sizeof(rsp) - sizeof(uint32_t))))) {
            ret = she_plat_ind_to_she_err_t(rsp.rsp_code);
            *sreg = 0;
            plat_os_abs_memset(id, 0u, SHE_ID_SIZE);
            plat_os_abs_memset(mac, 0u, SHE_MAC_SIZE);
            hdl->cancel = 0u;
            break;
        }

        /* Success: copy sreg , id and cmac reported by Secure-Enclave Platform, to output.*/
        *sreg = rsp.sreg;
        plat_os_abs_memcpy(id, rsp.id, SHE_ID_SIZE);
        plat_os_abs_memcpy(mac, rsp.mac, SHE_MAC_SIZE);

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


she_err_t she_get_info(struct she_hdl_s *hdl,
		       uint32_t *user_sab_id,
		       uint8_t *chip_unique_id,
		       uint16_t *chip_monotonic_counter,
		       uint16_t *chip_life_cycle,
		       uint32_t *she_version)
{
	uint32_t plat_rsp_code = SAB_NO_MESSAGE_RATING;
	she_err_t ret;
	op_get_info_args_t args;
	int32_t error;

	do {
		error = process_sab_msg(hdl->phdl,
				hdl->mu_type,
				SAB_GET_INFO_REQ,
				MT_SAB_GET_INFO,
				hdl->session_handle,
				&args, &plat_rsp_code);

		hdl->last_rating = plat_rsp_code;
		if ((GET_STATUS_CODE(plat_rsp_code) != SAB_SUCCESS_STATUS)
				|| (error != SAB_SUCCESS_STATUS)) {
			ret = she_plat_ind_to_she_err_t(plat_rsp_code);
			break;
		}

		*user_sab_id = args.user_sab_id;
		plat_os_abs_memcpy(chip_unique_id,
				   (uint8_t *)(&args.chip_unique_id),
				   args.chip_unq_id_sz);
		*chip_monotonic_counter = args.chip_monotonic_counter;
		*chip_life_cycle = args.chip_life_cycle;
		*she_version = args.version;

		/* Success. */
		ret = ERC_NO_ERROR;
	} while (false);

	return ret;
}
