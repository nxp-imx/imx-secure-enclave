
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

struct she_hdl_s {
	struct she_platform_hdl *phdl;
};

/* Helper function to send a message and wait for the response. Return 0 on success.*/
static int32_t she_send_msg_and_get_resp(struct she_hdl_s *hdl, uint8_t *cmd, uint32_t cmd_len, uint8_t *rsp, uint32_t rsp_len)
{
	int32_t err = -1;
	uint32_t len;
	uint32_t msg_size, crc;
	uint8_t i;

	do {
		/* If a command is longer than 4 words then compute a CRC
		 * and place it in the last word (space already allocated for this in cmd_len).
		 */
		msg_size = cmd_len / sizeof(uint32_t);
		if(msg_size > 4) {
			((uint32_t*)cmd) [msg_size - 1] = 0;

			for (i = 0; i < msg_size - 1; i++) {
				((uint32_t*)cmd) [msg_size - 1] ^= ((uint32_t*)cmd) [i];
			}
		}

		/* Send the command. */
		len = she_platform_send_mu_message(hdl->phdl, cmd, cmd_len);
		if (len != cmd_len) {
			break;
		}
		/* Read the response. */
		len = she_platform_read_mu_message(hdl->phdl, rsp, rsp_len);
		if (len != rsp_len) {
			break;
		}

		/* Check the CRC of the received message if more than 4 words. */
		msg_size = rsp_len / sizeof(uint32_t);
		if(msg_size > 4) {
			crc = 0;
			for (i = 0; i < msg_size - 1; i++) {
				crc ^= ((uint32_t*)rsp) [i];
			}

			if (crc != 	((uint32_t*)rsp) [msg_size - 1]) {
				break;
			}
		}

		err = 0;
	} while (0);
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
	if (hdl) {
		if (hdl->phdl) {
			she_platform_close_session(hdl->phdl);
		}
		free(hdl);
	}
}


/* Open a SHE user session and return a pointer to the session handle. */
struct she_hdl_s *she_open_session(void)
{
	struct she_cmd_init_msg cmd;
	struct she_cmd_init_rsp rsp;
	struct she_hdl_s *hdl = NULL;
	int32_t error = 1;

	do {
		/* allocate the handle (free when closing the session). */
		hdl = malloc(sizeof(struct she_hdl_s));
		if (!hdl) {
			break;
		}

		/* Open the SHE session. */
		hdl->phdl = she_platform_open_she_session();
		if (!hdl->phdl) {
			break;
		}

		/* Send the init command to Seco. */
		she_fill_cmd_msg_hdr(&cmd.hdr, AHAB_SHE_INIT, sizeof(struct she_cmd_init_msg));
		error = she_send_msg_and_get_resp(hdl,
					(uint8_t *)&cmd, sizeof(struct she_cmd_init_msg),
					(uint8_t *)&rsp, sizeof(struct she_cmd_init_rsp));
		if (error) {
			break;
		}

		/* Configure the shared buffer. and start the NVM manager. */
		error = she_platform_configure_shared_buf(hdl->phdl, rsp.shared_buf_offset, rsp.shared_buf_size);
		if (error) {
			break;
		}

		/* Success. */
		error = 0;
	} while (0);

	/* Clean-up in case of error. */
	if (error && hdl) {
		she_close_session(hdl);
		hdl = NULL;
	}
	return hdl;
};



/* MAC generation command processing. */
she_err_t she_cmd_generate_mac(struct she_hdl_s *hdl, uint8_t key_ext, uint8_t key_id, uint32_t message_length, uint8_t *message, uint8_t *mac)
{
	struct she_cmd_generate_mac_msg cmd;
	struct she_cmd_generate_mac_rsp rsp;
	int32_t error;
	she_err_t err = ERC_GENERAL_ERROR;

	do {
		/* Build command message. */
		she_fill_cmd_msg_hdr(&cmd.hdr, AHAB_SHE_CMD_GENERATE_MAC, sizeof(struct she_cmd_generate_mac_msg));
		cmd.key_id = (uint16_t)key_ext | (uint16_t)key_id;
		cmd.data_length = message_length;
		cmd.data_offset = she_platform_data_buf(hdl->phdl, message, message_length, DATA_BUF_IS_INPUT | DATA_BUF_USE_SEC_MEM | DATA_BUF_SHORT_ADDR) & SEC_MEM_SHORT_ADDR_MASK;
		cmd.mac_offset = she_platform_data_buf(hdl->phdl, mac, SHE_MAC_SIZE, DATA_BUF_USE_SEC_MEM | DATA_BUF_SHORT_ADDR) & SEC_MEM_SHORT_ADDR_MASK;

		/* Send the message to Seco. */
		error = she_send_msg_and_get_resp(hdl,
					(uint8_t *)&cmd, sizeof(struct she_cmd_generate_mac_msg),
					(uint8_t *)&rsp, sizeof(struct she_cmd_generate_mac_rsp));
		if (error) {
			break;
		}

		if (rsp.rsp_code != AHAB_SUCCESS_IND) {
			err = she_seco_ind_to_she_err_t(rsp.rsp_code);
			break;
		}

		/* Success. */
		err = ERC_NO_ERROR;
	} while (0);

	return err;
}

/* MAC verify command processing. */
she_err_t she_cmd_verify_mac(struct she_hdl_s *hdl, uint8_t key_ext, uint8_t key_id, uint32_t message_length, uint8_t *message, uint8_t *mac, uint8_t mac_length, uint8_t *verification_status)
{
	struct she_cmd_verify_mac_msg cmd;
	struct she_cmd_verify_mac_rsp rsp;
	int32_t error;
	she_err_t ret = ERC_GENERAL_ERROR;

	do {
		/* Build command message. */
		she_fill_cmd_msg_hdr(&cmd.hdr, AHAB_SHE_CMD_VERIFY_MAC, sizeof(struct she_cmd_verify_mac_msg));
		cmd.key_id = (uint16_t)key_ext | (uint16_t)key_id;
		cmd.data_length = message_length;
		/* input message at offset 0. MAC just after at offset "message_length". */
		cmd.data_offset = (uint16_t) she_platform_data_buf(hdl->phdl, message, message_length, DATA_BUF_IS_INPUT | DATA_BUF_USE_SEC_MEM | DATA_BUF_SHORT_ADDR);
		cmd.mac_offset = (uint16_t) she_platform_data_buf(hdl->phdl, mac, SHE_MAC_SIZE, DATA_BUF_IS_INPUT | DATA_BUF_USE_SEC_MEM | DATA_BUF_SHORT_ADDR);
		cmd.mac_length = mac_length;

		/* Send the message to Seco. */
		error = she_send_msg_and_get_resp(hdl,
					(uint8_t *)&cmd, sizeof(struct she_cmd_verify_mac_msg),
					(uint8_t *)&rsp, sizeof(struct she_cmd_verify_mac_rsp));
		if (error) {
			break;
		}

		if (rsp.rsp_code != AHAB_SUCCESS_IND) {
			ret = she_seco_ind_to_she_err_t(rsp.rsp_code);
			break;
		}

		/* Command success: Report the verification status. */
		*verification_status = (rsp.verification_status == 0 ? SHE_MAC_VERIFICATION_SUCCESS : SHE_MAC_VERIFICATION_FAILED);
		ret = ERC_NO_ERROR;
	} while (0);

	/* Force the status to fail in case of processing error. */
	if (ret != ERC_NO_ERROR) {
		*verification_status = SHE_MAC_VERIFICATION_FAILED;
	}

	return ret;
}

/* Generic function for encryption and decryption. */
static she_err_t she_cmd_cipher(struct she_hdl_s *hdl, uint8_t key_ext, uint8_t key_id, uint32_t data_length, uint8_t *iv, uint8_t *input, uint8_t *output, uint8_t flags, uint8_t algo)
{
	struct she_cmd_cipher_msg cmd;
	struct she_cmd_cipher_rsp rsp;
	int32_t error;
	uint64_t seco_iv_addr, seco_input_addr, seco_output_addr;
	she_err_t err = ERC_GENERAL_ERROR;

	do {
		/* Build command message. */
		she_fill_cmd_msg_hdr(&cmd.hdr, AHAB_SHE_CMD_CIPHER_REQ, sizeof(struct she_cmd_cipher_msg));

		cmd.key_id = (uint16_t)key_ext | (uint16_t)key_id;
		cmd.algo = algo;
		cmd.flags = flags;
		if (algo != SHE_CIPHER_ALGO_ECB) {
			seco_iv_addr = she_platform_data_buf(hdl->phdl, iv, SHE_AES_BLOCK_SIZE_128, DATA_BUF_IS_INPUT | DATA_BUF_USE_SEC_MEM);
		} else {
			seco_iv_addr = 0;
		}
		seco_input_addr = she_platform_data_buf(hdl->phdl, input, data_length, DATA_BUF_IS_INPUT | DATA_BUF_USE_SEC_MEM);
		seco_output_addr = she_platform_data_buf(hdl->phdl, output, data_length, DATA_BUF_USE_SEC_MEM);

		cmd.inputs_address_ext = (seco_input_addr >> 32) & 0xFFFFFFFF;
		/* all inputs addresses must have same 32bits MSB . */
		if ((algo != SHE_CIPHER_ALGO_ECB) && (cmd.inputs_address_ext != (seco_iv_addr >> 32) & 0xFFFFFFFF)) {
			break;
		}
		cmd.outputs_address_ext =  (seco_output_addr >> 32) & 0xFFFFFFFF;;
		/* Keep same layout in secure ram even for algos not using IV to simplify code here. */
		cmd.iv_address = seco_iv_addr & 0xFFFFFFFF;
		cmd.input_address = seco_input_addr & 0xFFFFFFFF;
		cmd.output_address = seco_output_addr & 0xFFFFFFFF;
		cmd.data_length = data_length;

		/* Send the message to Seco. */
		error = she_send_msg_and_get_resp(hdl,
					(uint8_t *)&cmd, sizeof(struct she_cmd_cipher_msg),
					(uint8_t *)&rsp, sizeof(struct she_cmd_cipher_rsp));
		if (error) {
			break;
		}

		if (rsp.rsp_code != AHAB_SUCCESS_IND) {
			err = she_seco_ind_to_she_err_t(rsp.rsp_code);
			break;
		}

		err = ERC_NO_ERROR;
	} while (0);

	return err;
}

/* CBC encrypt command. */
she_err_t she_cmd_enc_cbc(struct she_hdl_s *hdl, uint8_t key_ext, uint8_t key_id, uint32_t data_length, uint8_t *iv, uint8_t *plaintext, uint8_t *ciphertext)
{
	return she_cmd_cipher(hdl, key_ext, key_id, data_length, iv, plaintext, ciphertext, SHE_CIPHER_FLAG_ENCRYPT, SHE_CIPHER_ALGO_CBC);
}

/* CBC decrypt command. */
she_err_t she_cmd_dec_cbc(struct she_hdl_s *hdl, uint8_t key_ext, uint8_t key_id, uint32_t data_length, uint8_t *iv, uint8_t *ciphertext, uint8_t *plaintext)
{
	return she_cmd_cipher(hdl, key_ext, key_id, data_length, iv, ciphertext, plaintext, SHE_CIPHER_FLAG_DECRYPT, SHE_CIPHER_ALGO_CBC);
}

/* ECB encrypt command. */
she_err_t she_cmd_enc_ecb(struct she_hdl_s *hdl, uint8_t key_ext, uint8_t key_id, uint8_t *plaintext, uint8_t *ciphertext)
{
	return she_cmd_cipher(hdl, key_ext, key_id, SHE_AES_BLOCK_SIZE_128, NULL, plaintext, ciphertext, SHE_CIPHER_FLAG_ENCRYPT, SHE_CIPHER_ALGO_ECB);
}

/* ECB decrypt command. */
she_err_t she_cmd_dec_ecb(struct she_hdl_s *hdl, uint8_t key_ext, uint8_t key_id, uint8_t *ciphertext, uint8_t *plaintext)
{
	return she_cmd_cipher(hdl, key_ext, key_id, SHE_AES_BLOCK_SIZE_128, NULL, ciphertext, plaintext, SHE_CIPHER_FLAG_DECRYPT, SHE_CIPHER_ALGO_ECB);
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
		she_fill_cmd_msg_hdr(&cmd.hdr, AHAB_SHE_CMD_LOAD_KEY, sizeof(struct she_cmd_load_key_msg));

		/* Send the message to Seco. */
		error = she_send_msg_and_get_resp(hdl,
					(uint8_t *)&cmd, sizeof(struct she_cmd_load_key_msg),
					(uint8_t *)&rsp, sizeof(struct she_cmd_load_key_rsp));
		if (error) {
			break;
		}

		if (rsp.rsp_code != AHAB_SUCCESS_IND) {
			err = she_seco_ind_to_she_err_t(rsp.rsp_code);
			break;
		}

		/* Success. */
		err = ERC_NO_ERROR;
	} while (0);

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
