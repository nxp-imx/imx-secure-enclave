
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
#include <string.h>

#define SHE_DEFAULT_DID	0x0
#define SHE_DEFAULT_TZ	0x0
#define SHE_DEFAULT_MU	0x1


struct she_hdl_s {
	struct she_platform_hdl *phdl;
	uint32_t session_handle;
	uint32_t key_store_handle;
	uint32_t cipher_handle;
};

static uint32_t she_compute_msg_crc(uint32_t *msg, uint32_t msg_len) {
	uint32_t crc;
	uint32_t i;
	uint32_t nb_words = msg_len / (uint32_t)sizeof(uint32_t);

	crc = 0u;
	for (i = 0u; i < nb_words; i++) {
		crc ^= *(msg + i);
	}
	return crc;
}


/* Helper function to send a message and wait for the response. Return 0 on success.*/
static int32_t she_send_msg_and_get_resp(struct she_hdl_s *hdl, uint32_t *cmd, uint32_t cmd_len, uint32_t *rsp, uint32_t rsp_len)
{
	int32_t err = -1;
	int32_t len;

	do {
		/* Command and response need to be at least 1 word for the header. */
		if ((cmd_len < (uint32_t)sizeof(uint32_t)) || (rsp_len < (uint32_t)sizeof(uint32_t))) {
			break;
		}

		/* Send the command. */
		len = she_platform_send_mu_message(hdl->phdl, cmd, cmd_len);
		if (len != (int32_t)cmd_len) {
			break;
		}
		/* Read the response. */
		len = she_platform_read_mu_message(hdl->phdl, rsp, rsp_len);
		if (len != (int32_t)rsp_len) {
			break;
		}

		err = 0;
	} while (false);
	return err;
}


/* Convert errors codes reported by Seco to SHE error codes. */
static she_err_t she_seco_ind_to_she_err_t (uint32_t rsp_code)
{
	she_err_t err = ERC_GENERAL_ERROR;
	switch (rsp_code) {
	/* 1 to 1 mapping for all SHE specific error codes. */
	case AHAB_SHE_ERC_SEQUENCE_ERROR_IND :
		err = ERC_SEQUENCE_ERROR;
		break;
	case AHAB_SHE_ERC_KEY_NOT_AVAILABLE_IND :
		err = ERC_KEY_NOT_AVAILABLE;
		break;
	case AHAB_SHE_ERC_KEY_INVALID_IND :
		err = ERC_KEY_INVALID;
		break;
	case AHAB_SHE_ERC_KEY_EMPTY_IND :
		err = ERC_KEY_EMPTY;
		break;
	case AHAB_SHE_ERC_NO_SECURE_BOOT_IND :
		err = ERC_NO_SECURE_BOOT;
		break;
	case AHAB_SHE_ERC_KEY_WRITE_PROTECTED_IND :
		err = ERC_KEY_WRITE_PROTECTED;
		break;
	case AHAB_SHE_ERC_KEY_UPDATE_ERROR_IND :
		err = ERC_KEY_UPDATE_ERROR;
		break;
	case AHAB_SHE_ERC_RNG_SEED_IND :
		err = ERC_RNG_SEED;
		break;
	case AHAB_SHE_ERC_NO_DEBUGGING_IND :
		err = ERC_NO_DEBUGGING;
		break;
	case AHAB_SHE_ERC_BUSY_IND :
		err = ERC_BUSY;
		break;
	case AHAB_SHE_ERC_MEMORY_FAILURE_IND :
		err = ERC_MEMORY_FAILURE;
		break;
	case AHAB_SHE_ERC_GENERAL_ERROR_IND :
		err = ERC_GENERAL_ERROR;
		break;
	/* All other SECO error codes. */
	default:
		err = ERC_GENERAL_ERROR;
		break;
	}
	return err;
}

/* Close a previously opened SHE session. */
void she_close_session(struct she_hdl_s *hdl) {
	struct she_cmd_session_close_msg cmd;
	struct she_cmd_session_close_rsp rsp;

	if (hdl != NULL) {
		if (hdl->phdl != NULL) {
			if (hdl -> session_handle) {
				/* Send the session close command to Seco. */
				she_fill_cmd_msg_hdr((struct she_mu_hdr *)&cmd, AHAB_SESSION_CLOSE, sizeof(struct she_cmd_session_close_msg));
				((struct she_cmd_session_close_msg *)&cmd)->sesssion_handle = hdl->session_handle;

				(void)she_send_msg_and_get_resp(hdl,
							(uint32_t *)&cmd, (uint32_t)sizeof(struct she_cmd_session_close_msg),
							(uint32_t *)&rsp, (uint32_t)sizeof(struct she_cmd_session_close_rsp));

				hdl -> session_handle = 0;
			}
			she_platform_close_session(hdl->phdl);
		}
		free(hdl);
	}
}

static she_err_t she_open_key_store(struct she_hdl_s *hdl, uint32_t key_storage_identifier, uint32_t password)
{
	struct she_cmd_key_store_open_msg cmd;
	struct she_cmd_key_store_open_rsp rsp;

	she_err_t err = ERC_GENERAL_ERROR;
	int32_t error = 1;
	do {

		if (hdl->session_handle == 0) {
			break;
		}

		/* Send the keys store open command to Seco. */
		she_fill_cmd_msg_hdr(&cmd.hdr, AHAB_KEY_STORE_OPEN, sizeof(struct she_cmd_key_store_open_msg));

		cmd.sesssion_handle = hdl->session_handle;
		cmd.key_store_id = key_storage_identifier;
		cmd.password = password;
		cmd.input_address_ext = 0;
		cmd.output_address_ext = 0;
		cmd.flags = 0;
		error = she_send_msg_and_get_resp(hdl,
					(uint32_t *)&cmd, (uint32_t)sizeof(struct she_cmd_key_store_open_msg),
					(uint32_t *)&rsp, (uint32_t)sizeof(struct she_cmd_key_store_open_rsp));

		if ((error != 0) || (rsp.rsp_code != AHAB_SUCCESS_IND)) {
			break;
		}

		hdl->key_store_handle = rsp.key_store_handle;
		/* Success. */
		err = ERC_NO_ERROR;
	} while(0);
	return err;
}

static she_err_t she_get_shared_bufer(struct she_hdl_s *hdl, uint32_t *shared_buf_offset, uint32_t *shared_buf_size)
{
	struct she_cmd_shared_buffer_msg cmd;
	struct she_cmd_shared_buffer_rsp rsp;

	she_err_t err = ERC_GENERAL_ERROR;
	int32_t error = 1;
	do {

		if (hdl->session_handle == 0) {
			break;
		}

		/* Send the keys store open command to Seco. */
		she_fill_cmd_msg_hdr(&cmd.hdr, AHAB_SHARED_BUF_REQ, sizeof(struct she_cmd_shared_buffer_msg));

		cmd.sesssion_handle = hdl->session_handle;
		error = she_send_msg_and_get_resp(hdl,
					(uint32_t *)&cmd, (uint32_t)sizeof(struct she_cmd_shared_buffer_msg),
					(uint32_t *)&rsp, (uint32_t)sizeof(struct she_cmd_shared_buffer_rsp));

		if ((error != 0) || (rsp.rsp_code != AHAB_SUCCESS_IND)) {
			break;
		}
		*shared_buf_offset = rsp.shared_buf_offset;
		*shared_buf_size = rsp.shared_buf_size;
		/* Success. */
		err = ERC_NO_ERROR;
	} while(0);
	return err;
}



static she_err_t she_close_key_store(struct she_hdl_s *hdl)
{
	struct she_cmd_key_store_close_msg cmd;
	struct she_cmd_key_store_close_rsp rsp;
	she_err_t err = ERC_GENERAL_ERROR;
	int32_t error = 1;
	do {

		if (hdl->key_store_handle == 0) {
			break;
		}
		/* Send the keys store close command to Seco. */
		she_fill_cmd_msg_hdr(&cmd.hdr, AHAB_KEY_STORE_CLOSE, sizeof(struct she_cmd_key_store_close_msg));
		cmd.key_store_handle = hdl->key_store_handle;

		error = she_send_msg_and_get_resp(hdl,
					(uint32_t *)&cmd, (uint32_t)sizeof(struct she_cmd_key_store_close_msg),
					(uint32_t *)&rsp, (uint32_t)sizeof(struct she_cmd_key_store_close_rsp));

		if ((error != 0) || (rsp.rsp_code != AHAB_SUCCESS_IND)) {
			break;
		}

		hdl->key_store_handle = 0;

		/* Success. */
		err = ERC_NO_ERROR;
	} while(0);
	return err;
}

static she_err_t she_open_cipher(struct she_hdl_s *hdl)
{
	struct she_cmd_cipher_open_msg cmd;
	struct she_cmd_cipher_open_rsp rsp;

	she_err_t err = ERC_GENERAL_ERROR;
	int32_t error = 1;
	do {

		if (hdl->cipher_handle != 0) {
			break;
		}
		/* Send the keys store open command to Seco. */
		she_fill_cmd_msg_hdr(&cmd.hdr, AHAB_CIPHER_OPEN, sizeof(struct she_cmd_cipher_open_msg));
		cmd.input_address_ext = 0;
		cmd.output_address_ext = 0;
		cmd.key_store_handle = hdl->key_store_handle;
		error = she_send_msg_and_get_resp(hdl,
					(uint32_t *)&cmd, (uint32_t)sizeof(struct she_cmd_cipher_open_msg),
					(uint32_t *)&rsp, (uint32_t)sizeof(struct she_cmd_cipher_open_rsp));

		if ((error != 0) || (rsp.rsp_code != AHAB_SUCCESS_IND)) {
			break;
		}

		hdl->cipher_handle = rsp.cipher_handle;
		/* Success. */
		err = ERC_NO_ERROR;
	} while(0);
	return error;
}

static she_err_t she_close_cipher(struct she_hdl_s *hdl)
{
	struct she_cmd_cipher_close_msg cmd;
	struct she_cmd_cipher_close_rsp rsp;
	she_err_t err = ERC_GENERAL_ERROR;
	int32_t error = 1;
	do {
		if (hdl->cipher_handle == 0){
			break;
		}
		/* Send the keys store open command to Seco. */
		she_fill_cmd_msg_hdr(&cmd.hdr, AHAB_CIPHER_CLOSE, sizeof(struct she_cmd_cipher_close_msg));
		cmd.cipher_handle = hdl->cipher_handle;
		error = she_send_msg_and_get_resp(hdl,
					(uint32_t *)&cmd, (uint32_t)sizeof(struct she_cmd_cipher_close_msg),
					(uint32_t *)&rsp, (uint32_t)sizeof(struct she_cmd_cipher_close_rsp));

		if ((error != 0) || (rsp.rsp_code != AHAB_SUCCESS_IND)) {
			break;
		}

		hdl->cipher_handle = 0;
		/* Success. */
		err = ERC_NO_ERROR;
	} while(0);
	return err;
}

/* Open a SHE user session and return a pointer to the session handle. */
struct she_hdl_s *she_open_session(uint32_t key_storage_identifier, uint32_t password)
{
	struct she_cmd_session_open_msg msg;
	struct she_cmd_session_open_rsp rsp;
	struct she_hdl_s *hdl = NULL;
	int32_t error = 1;
	uint32_t shared_buf_offset, shared_buf_size;
	do {
		/* allocate the handle (free when closing the session). */
		hdl = malloc(sizeof(struct she_hdl_s));
		if (hdl == NULL) {
			break;
		}
		memset(hdl, 0, sizeof(struct she_hdl_s));

		/* Open the SHE session. */
		hdl->phdl = she_platform_open_she_session();
		if (hdl->phdl == NULL) {
			break;
		}

		/* Send the session open command to Seco. */
		she_fill_cmd_msg_hdr((struct she_mu_hdr *)&msg, AHAB_SESSION_OPEN, sizeof(struct she_cmd_session_open_msg));
		msg.did = SHE_DEFAULT_DID;
		msg.tz = SHE_DEFAULT_TZ;
		msg.mu_id = SHE_DEFAULT_MU;
		msg.operating_mode = 0;
		msg.priority = 0;

		error = she_send_msg_and_get_resp(hdl,
					(uint32_t *)&msg, (uint32_t)sizeof(struct she_cmd_session_open_msg),
					(uint32_t *)&rsp, (uint32_t)sizeof(struct she_cmd_session_open_rsp));

		if ((error != 0) || (rsp.rsp_code != AHAB_SUCCESS_IND)) {
			error = 1 ;
			break;
		}

		hdl->session_handle = rsp.sesssion_handle;

		if (she_get_shared_bufer(hdl, &shared_buf_offset, &shared_buf_size) != ERC_NO_ERROR) {
			break;
		}

		/* Configure the shared buffer. and start the NVM manager. */
		error = she_platform_configure_shared_buf(hdl->phdl, shared_buf_offset, shared_buf_size);
		if (error != 0) {
			break;
		}

		if(she_open_key_store(hdl, key_storage_identifier, password) != ERC_NO_ERROR) {
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
	she_err_t err = ERC_GENERAL_ERROR;

	do {

		/* Build command message. */
		she_fill_cmd_msg_hdr(&cmd.hdr, AHAB_SHE_CMD_GENERATE_MAC, (uint32_t)sizeof(struct she_cmd_generate_mac_msg));
		cmd.key_id = (uint16_t)key_ext | (uint16_t)key_id;
		cmd.data_length = message_length;
		cmd.data_offset = (uint16_t)(she_platform_data_buf(hdl->phdl, message, message_length, DATA_BUF_IS_INPUT | DATA_BUF_USE_SEC_MEM | DATA_BUF_SHORT_ADDR) & SEC_MEM_SHORT_ADDR_MASK);
		cmd.mac_offset = (uint16_t)(she_platform_data_buf(hdl->phdl, mac, SHE_MAC_SIZE, DATA_BUF_USE_SEC_MEM | DATA_BUF_SHORT_ADDR) & SEC_MEM_SHORT_ADDR_MASK);

		/* Send the message to Seco. */
		error = she_send_msg_and_get_resp(hdl,
					(uint32_t *)&cmd, (uint32_t)sizeof(struct she_cmd_generate_mac_msg),
					(uint32_t *)&rsp, (uint32_t)sizeof(struct she_cmd_generate_mac_rsp));
		if (error != 0) {
			break;
		}

		if (rsp.rsp_code != AHAB_SUCCESS_IND) {
			err = she_seco_ind_to_she_err_t(rsp.rsp_code);
			break;
		}

		/* Success. */
		err = ERC_NO_ERROR;
	} while (false);

	return err;
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
		error = she_send_msg_and_get_resp(hdl,
					(uint32_t *)&cmd, (uint32_t)sizeof(struct she_cmd_verify_mac_msg),
					(uint32_t *)&rsp, (uint32_t)sizeof(struct she_cmd_verify_mac_rsp));
		if (error != 0) {
			break;
		}

		if (rsp.rsp_code != AHAB_SUCCESS_IND) {
			ret = she_seco_ind_to_she_err_t(rsp.rsp_code);
			break;
		}

		/* Command success: Report the verification status. */
		*verification_status = (rsp.verification_status == (uint32_t)0 ? SHE_MAC_VERIFICATION_SUCCESS : SHE_MAC_VERIFICATION_FAILED);
		ret = ERC_NO_ERROR;
	} while (false);

	/* Force the status to fail in case of processing error. */
	if (ret != ERC_NO_ERROR) {
		*verification_status = SHE_MAC_VERIFICATION_FAILED;
	}

	return ret;
}

/* Generic function for encryption and decryption. */
static she_err_t she_cmd_cipher(struct she_hdl_s *hdl, uint8_t key_ext, uint8_t key_id, uint32_t data_length, uint8_t *iv, uint8_t *input, uint8_t *output, uint8_t flags, uint8_t algo)
{
	struct she_cmd_cipher_one_go_msg cmd;
	struct she_cmd_cipher_one_go_rsp rsp;
	uint32_t len;
	uint32_t shared_mem_offset;
	int32_t error;
	uint64_t seco_iv_addr, seco_input_addr, seco_output_addr;
	uint16_t iv_size;
	she_err_t err = ERC_GENERAL_ERROR;

	do {
		if(she_open_cipher(hdl) != 0) {
			break;
		}

		/* Build command message. */
		she_fill_cmd_msg_hdr(&cmd.hdr, AHAB_SHE_CMD_CIPHER_REQ, (uint32_t)sizeof(struct she_cmd_cipher_one_go_msg));
		cmd.cipher_handle = hdl->cipher_handle;
		cmd.key_id = (uint16_t)key_ext | (uint16_t)key_id;		cmd.algo = algo;
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
		error = she_send_msg_and_get_resp(hdl,
					(uint32_t *)&cmd, (uint32_t)sizeof(struct she_cmd_cipher_one_go_msg),
					(uint32_t *)&rsp, (uint32_t)sizeof(struct she_cmd_cipher_one_go_rsp));
		if (error) {
			break;
		}

		if (rsp.rsp_code != AHAB_SUCCESS_IND) {
			err = she_seco_ind_to_she_err_t(rsp.rsp_code);
			break;
		}

		err = ERC_NO_ERROR;
	} while (false);

	if(she_close_cipher(hdl) != 0) {
		err = ERC_GENERAL_ERROR;
	}


	return err;
}

/* CBC encrypt command. */
she_err_t she_cmd_enc_cbc(struct she_hdl_s *hdl, uint8_t key_ext, uint8_t key_id, uint32_t data_length, uint8_t *iv, uint8_t *plaintext, uint8_t *ciphertext)
{
	return she_cmd_cipher(hdl, key_ext, key_id, data_length, iv, plaintext, ciphertext, AHAB_CIPHER_ONE_GO_FLAGS_ENCRYPT, AHAB_CIPHER_ONE_GO_ALGO_CBC);
}

/* CBC decrypt command. */
she_err_t she_cmd_dec_cbc(struct she_hdl_s *hdl, uint8_t key_ext, uint8_t key_id, uint32_t data_length, uint8_t *iv, uint8_t *ciphertext, uint8_t *plaintext)
{
	return she_cmd_cipher(hdl, key_ext, key_id, data_length, iv, ciphertext, plaintext, AHAB_CIPHER_ONE_GO_FLAGS_DECRYPT, AHAB_CIPHER_ONE_GO_ALGO_CBC);
}

/* ECB encrypt command. */
she_err_t she_cmd_enc_ecb(struct she_hdl_s *hdl, uint8_t key_ext, uint8_t key_id, uint8_t *plaintext, uint8_t *ciphertext)
{
	return she_cmd_cipher(hdl, key_ext, key_id, SHE_AES_BLOCK_SIZE_128, NULL, plaintext, ciphertext, AHAB_CIPHER_ONE_GO_FLAGS_ENCRYPT, AHAB_CIPHER_ONE_GO_ALGO_ECB);
}

/* ECB decrypt command. */
she_err_t she_cmd_dec_ecb(struct she_hdl_s *hdl, uint8_t key_ext, uint8_t key_id, uint8_t *ciphertext, uint8_t *plaintext)
{
	return she_cmd_cipher(hdl, key_ext, key_id, SHE_AES_BLOCK_SIZE_128, NULL, ciphertext, plaintext, AHAB_CIPHER_ONE_GO_FLAGS_DECRYPT, AHAB_CIPHER_ONE_GO_ALGO_ECB);
}

/* Load key command processing. */
she_err_t she_cmd_load_key(struct she_hdl_s *hdl, uint8_t *m1, uint8_t *m2, uint8_t *m3, uint8_t *m4, uint8_t *m5)
{
	struct she_cmd_load_key_msg cmd;
	struct she_cmd_load_key_rsp rsp;
	int32_t error;
	she_err_t err = ERC_GENERAL_ERROR;

	do {
		/* Build command message. */
		she_fill_cmd_msg_hdr(&cmd.hdr, AHAB_SHE_CMD_LOAD_KEY, (uint32_t)sizeof(struct she_cmd_load_key_msg));

		/* Send the message to Seco. */
		error = she_send_msg_and_get_resp(hdl,
					(uint32_t *)&cmd, (uint32_t)sizeof(struct she_cmd_load_key_msg),
					(uint32_t *)&rsp, (uint32_t)sizeof(struct she_cmd_load_key_rsp));
		if (error != 0) {
			break;
		}

		if (rsp.rsp_code != AHAB_SUCCESS_IND) {
			err = she_seco_ind_to_she_err_t(rsp.rsp_code);
			break;
		}

		/* Success. */
		err = ERC_NO_ERROR;
	} while (false);

	return err;
}

she_err_t she_cmd_load_plain_key(struct she_hdl_s *hdl, uint8_t *key) {
	she_err_t err = ERC_GENERAL_ERROR;

	return err;
}


she_err_t she_cmd_export_ram_key(struct she_hdl_s *hdl, uint8_t *m1, uint8_t *m2, uint8_t *m3, uint8_t *m4, uint8_t *m5) {
	she_err_t err = ERC_GENERAL_ERROR;

	return err;
}

she_err_t she_cmd_init_rng(struct she_hdl_s *hdl) {
	she_err_t err = ERC_GENERAL_ERROR;

	return err;
}


she_err_t she_cmd_extend_seed(struct she_hdl_s *hdl, uint8_t *entropy) {
	she_err_t err = ERC_GENERAL_ERROR;

	return err;
}


she_err_t she_cmd_rnd(struct she_hdl_s *hdl, uint8_t *rnd) {
	she_err_t err = ERC_GENERAL_ERROR;

	return err;
}


she_err_t she_cmd_get_status(struct she_hdl_s *hdl, uint8_t *sreg) {
	she_err_t err = ERC_GENERAL_ERROR;

	return err;
}


she_err_t she_cmd_get_id(struct she_hdl_s *hdl, uint8_t *challenge, uint8_t *id, uint8_t *sreg, uint8_t *mac) {
	she_err_t err = ERC_GENERAL_ERROR;

	return err;
}


she_err_t she_cmd_cancel(struct she_hdl_s *hdl) {
	she_err_t err = ERC_GENERAL_ERROR;

	return err;
}
