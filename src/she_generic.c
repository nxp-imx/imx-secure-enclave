
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
#include "she_nvm.h"
#include "she_platform.h"

struct she_hdl {
	struct she_platform_hdl *phdl;
};


/* Helper function to send a message and wait for the response. Return 0 on success.*/
static int32_t she_send_msg_and_get_resp(struct she_hdl *hdl, uint8_t *cmd, uint32_t cmd_len, uint8_t *rsp, uint32_t rsp_len)
{
	int32_t err = -1;
	uint32_t len;
	uint32_t msg_size, crc;
	uint8_t i;

	do {

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


/* Close a previously opened SHE session. */
void she_close_session(struct she_hdl *hdl) {
	if (hdl) {
		if (hdl->phdl) {
			she_platform_close_session(hdl->phdl);
		}
		free(hdl);
	}
}


/* Open a SHE user session and return a pointer to the session handle. */
struct she_hdl *she_open_session(void)
{
	struct she_cmd_init cmd;
	struct she_rsp_init rsp;
	struct she_hdl *hdl = NULL;
	int32_t error = 1;

	do {
		/* allocate the handle (free when closing the session). */
		hdl = malloc(sizeof(struct she_hdl));
		if (!hdl) {
			break;
		}

		/* Open the SHE session. */
		hdl->phdl = she_platform_open_session(SHE_USER);
		if (!hdl->phdl) {
			break;
		}

		/* Send the init command to Seco. */
		she_fill_cmd_msg_hdr(&cmd.hdr, AHAB_SHE_INIT, sizeof(struct she_cmd_init));
		error = she_send_msg_and_get_resp(hdl,
					(uint8_t *)&cmd, sizeof(struct she_cmd_init),
					(uint8_t *)&rsp, sizeof(struct she_rsp_init));
		if (error) {
			break;
		}

		/* Configure the shared buffer. and start the NVM manager. */
		error = she_platform_configure_shared_buf(hdl->phdl, rsp.shared_buf_offset, rsp.shared_buf_size);
		if (error) {
			break;
		}

		/* Start the NVM manager. (it currently needs the shared memory so cannot start it earlier)*/
		error = she_nvm_init(rsp.shared_buf_offset, rsp.shared_buf_size);
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
she_err she_cmd_generate_mac(struct she_hdl *hdl, uint8_t key_id, uint32_t message_length, uint8_t *message, uint8_t *mac)
{
	struct she_cmd_generate_mac cmd;
	struct she_rsp_generate_mac rsp;
	uint32_t len;
	int32_t error;
	she_err err = ERC_GENERAL_ERROR;

	do {
		/* Copy the message to the shared buffer at offset 0. */
		len = she_platform_copy_to_shared_buf(hdl->phdl, 0x0, message, message_length);
		if (len != message_length) {
			break;
		}

		/* Build command message. */
		she_fill_cmd_msg_hdr(&cmd.hdr, AHAB_SHE_CMD_GENERATE_MAC, sizeof(struct she_cmd_generate_mac));
		cmd.key_id = key_id;
		cmd.data_length = message_length;
		/* input data at offset 0. Output just after at offset "message_length". */
		cmd.data_offset = she_platform_shared_buf_offset(hdl->phdl) + 0x00;
		cmd.mac_offset = she_platform_shared_buf_offset(hdl->phdl) + message_length;

		/* Send the message to Seco. */
		error = she_send_msg_and_get_resp(hdl,
					(uint8_t *)&cmd, sizeof(struct she_cmd_generate_mac),
					(uint8_t *)&rsp, sizeof(struct she_rsp_generate_mac));
		if (error) {
			break;
		}

		// TODO: map Seco error codes to SHE errors
		if (rsp.rsp_code != AHAB_SUCCESS_IND) {
			break;
		}

		/* Get the result from shared memory (at offset "message_length". */
		len = she_platform_copy_from_shared_buf(hdl->phdl, message_length, mac, SHE_MAC_SIZE);
		if (len != SHE_MAC_SIZE) {
			break;
		}

		/* Success. */
		err = ERC_NO_ERROR;
	} while (0);

	return err;
}

/* MAC verify command processing. */
she_err she_cmd_verify_mac(struct she_hdl *hdl, uint8_t key_id, uint32_t message_length, uint8_t *message, uint8_t *mac, uint8_t mac_length, uint8_t *verification_status)
{
	struct she_cmd_verify_mac cmd;
	struct she_rsp_verify_mac rsp;
	uint32_t len;
	uint32_t shared_mem_offset;
	int32_t error;
	she_err err = ERC_GENERAL_ERROR;

	do {
		/* Copy the message to shared memory at offset 0. */
		len = she_platform_copy_to_shared_buf(hdl->phdl, 0x0, message, message_length);
		if (len != message_length) {
			break;
		}
		/* Copy the MAC to shared memory just after the message at offset "message_length". */
		len = she_platform_copy_to_shared_buf(hdl->phdl, message_length, mac, mac_length);
		if (len != mac_length) {
			break;
		}

		/* Build command message. */
		she_fill_cmd_msg_hdr(&cmd.hdr, AHAB_SHE_CMD_VERIFY_MAC, sizeof(struct she_cmd_verify_mac));
		cmd.key_id = key_id;
		cmd.data_length = message_length;
		/* input message at offset 0. MAC just after at offset "message_length". */
		shared_mem_offset = she_platform_shared_buf_offset(hdl->phdl);
		cmd.data_offset = shared_mem_offset + 0x00;
		cmd.mac_offset = shared_mem_offset + message_length;
		cmd.mac_length = mac_length;


		/* Send the message to Seco. */
		error = she_send_msg_and_get_resp(hdl,
					(uint8_t *)&cmd, sizeof(struct she_cmd_verify_mac),
					(uint8_t *)&rsp, sizeof(struct she_rsp_verify_mac));
		if (error) {
			break;
		}

		// TODO: map Seco error codes to SHE errors
		if (rsp.rsp_code != AHAB_SUCCESS_IND) {
			break;
		}

		/* Command success: Report the verification status. */
		*verification_status = (rsp.verification_status == 0 ? SHE_MAC_VERIFICATION_SUCCESS : SHE_MAC_VERIFICATION_FAILED);
		err = ERC_NO_ERROR;
	} while (0);

	/* Force the status to fail in case of processing error. */
	if (err != ERC_NO_ERROR) {
		*verification_status = SHE_MAC_VERIFICATION_FAILED;
	}

	return err;
}


/* CBC encrypt command. */
she_err she_cmd_enc_cbc(struct she_hdl *hdl, uint8_t key_id, uint32_t data_length, uint8_t *iv, uint8_t *plaintext, uint8_t *ciphertext)
{	struct she_cmd_enc_cbc cmd;
	struct she_rsp_enc_cbc rsp;
	uint32_t len;
	uint32_t shared_mem_offset;
	int32_t error;
	she_err err = ERC_GENERAL_ERROR;

	do {
		/* Copy the IV to shared memory at offset 0. */
		len = she_platform_copy_to_shared_buf(hdl->phdl, 0, iv, SHE_CBC_BLOCK_SIZE_128);
		if (len != SHE_CBC_BLOCK_SIZE_128) {
			break;
		}
		/* Copy the data to shared memory just after the IV at offset "SHE_CBC_BLOCK_SIZE_128". */
		len = she_platform_copy_to_shared_buf(hdl->phdl, SHE_CBC_BLOCK_SIZE_128, plaintext, data_length);
		if (len != data_length) {
			break;
		}

		/* Build command message. */
		she_fill_cmd_msg_hdr(&cmd.hdr, AHAB_SHE_CMD_ENC_CBC_REQ, sizeof(struct she_cmd_enc_cbc));
		cmd.key_id = key_id;
		/* IV at offset 0. input data just after at offset SHE_CBC_BLOCK_SIZE_128. Then output data at offset (n+1)block_size. */
		shared_mem_offset = she_platform_shared_buf_offset(hdl->phdl);
		cmd.iv_offset = shared_mem_offset + 0x00;
		cmd.data_offset = shared_mem_offset + SHE_CBC_BLOCK_SIZE_128;
		cmd.output_offset = shared_mem_offset + SHE_CBC_BLOCK_SIZE_128 + data_length;
		cmd.data_length = data_length;

		/* Send the message to Seco. */
		error = she_send_msg_and_get_resp(hdl,
					(uint8_t *)&cmd, sizeof(struct she_cmd_enc_cbc),
					(uint8_t *)&rsp, sizeof(struct she_rsp_enc_cbc));
		if (error) {
			break;
		}

		// TODO: map Seco error codes to SHE errors
		if (rsp.rsp_code != AHAB_SUCCESS_IND) {
			break;
		}

		/* Get the result from shared memory. */
		len = she_platform_copy_from_shared_buf(hdl->phdl, SHE_CBC_BLOCK_SIZE_128 + data_length, ciphertext, data_length);
		if (len != data_length) {
			break;
		}

		err = ERC_NO_ERROR;
	} while (0);

	return err;
}


/* Load key command processing. */
she_err she_cmd_load_key(struct she_hdl *hdl)
{
	struct she_cmd_load_key cmd;
	struct she_rsp_load_key rsp;
	uint32_t len;
	int32_t error;
	she_err err = ERC_GENERAL_ERROR;

	do {
		/* Build command message. */
		she_fill_cmd_msg_hdr(&cmd.hdr, AHAB_SHE_CMD_LOAD_KEY, sizeof(struct she_cmd_load_key));

		/* Send the message to Seco. */
		error = she_send_msg_and_get_resp(hdl,
					(uint8_t *)&cmd, sizeof(struct she_cmd_load_key),
					(uint8_t *)&rsp, sizeof(struct she_rsp_load_key));
		if (error) {
			break;
		}

		// TODO: map Seco error codes to SHE errors
		if (rsp.rsp_code != AHAB_SUCCESS_IND) {
			break;
		}

		/* Success. */
		err = ERC_NO_ERROR;
	} while (0);

	return err;
}
