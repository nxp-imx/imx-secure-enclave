
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

#include <stdio.h>

#include "she_msg.h"
#include "she_platform.h"


she_hdl *she_open_session(void) {
	struct she_cmd_init cmd;
	struct she_rsp_init rsp;
	int len;

	/* Open the SHE session. */
	she_hdl *hdl = she_platform_open_session();
	if (!hdl) {
		printf("open session error\n");
		return NULL;
	}

	/* Send the init command to Seco. */
	cmd.hdr.tag = MESSAGING_TAG_COMMAND;
	cmd.hdr.command = AHAB_SHE_INIT;
	cmd.hdr.size = sizeof(struct she_cmd_init) / sizeof(uint32_t);
	cmd.hdr.ver = MESSAGING_VERSION_2;
	len = she_platform_send_mu_message(hdl, (char *)&cmd, sizeof(struct she_cmd_init));
	if (len != sizeof(struct she_cmd_init)) {
		printf("she_open_session write error len:0x%x\n", len);
		she_platform_close_session(hdl);
		return NULL;
	}

	/* Read the response. */
	len = she_platform_read_mu_message(hdl, (char *)&rsp, sizeof(struct she_rsp_init));
	if (len != sizeof(struct she_rsp_init)) {
		printf("she_open_session read error len:0x%x\n", len);
		she_platform_close_session(hdl);
		return NULL;
	}

	/* Configure the shared buffer. */
	she_platform_configure_shared_buf(hdl, (void *)(uintptr_t)(rsp.shared_buf_offset), rsp.shared_buf_size);

	return hdl;
};


void she_close_session(she_hdl *hdl) {
	she_platform_close_session(hdl);
}


she_err she_cmd_generate_mac(she_hdl *hdl, uint8_t key_id, uint64_t message_length, uint8_t *message, uint8_t *mac)
{

	struct she_cmd_generate_mac cmd;
	struct she_rsp_generate_mac rsp;
	int len;

	she_platform_copy_to_shared_buf(hdl, 0x0, message, message_length);

	cmd.hdr.tag = MESSAGING_TAG_COMMAND;
	cmd.hdr.command = AHAB_SHE_CMD_GENERATE_MAC;
	cmd.hdr.size = sizeof(struct she_cmd_generate_mac) / sizeof(uint32_t);
	cmd.hdr.ver = MESSAGING_VERSION_2;

	cmd.key_id = key_id;
    cmd.data_length = message_length;
    cmd.data_offset = she_platform_shared_buf_offset(hdl) + 0x00;
    cmd.mac_offset = she_platform_shared_buf_offset(hdl) + message_length;

	len = she_platform_send_mu_message(hdl, (char *)&cmd, sizeof(struct she_cmd_generate_mac));
	if (len != sizeof(struct she_cmd_generate_mac)) {
		return ERC_GENERAL_ERROR;
	}

	/* Read the response. */
	len = she_platform_read_mu_message(hdl, (char *)&rsp, sizeof(struct she_rsp_generate_mac));
	if (len != sizeof(struct she_rsp_generate_mac)) {
		printf("she_cmd_generate_mac read len:0x%x\n", len);
		return ERC_GENERAL_ERROR;
	}

	if (rsp.rsp_code != AHAB_SUCCESS_IND) {
		printf("she_cmd_generate_mac response error:0x%x\n", rsp.rsp_code);
		// TODO: map Seco error codes to SHE errors
		return ERC_GENERAL_ERROR;
	}

	she_platform_copy_from_shared_buf(hdl, message_length /*Mac offset */, mac, SHE_MAC_SIZE);

	return ERC_NO_ERROR;
}


she_err she_cmd_verify_mac(she_hdl *hdl, uint8_t key_id, uint64_t message_length, uint8_t *message, uint8_t *mac, uint8_t mac_length, uint8_t *verification_status)
{

	struct she_cmd_verify_mac cmd;
	struct she_rsp_verify_mac rsp;
	int len;

	she_platform_copy_to_shared_buf(hdl, 0x0, message, message_length);
	she_platform_copy_to_shared_buf(hdl, message_length, mac, mac_length);

	cmd.hdr.tag = MESSAGING_TAG_COMMAND;
	cmd.hdr.command = AHAB_SHE_CMD_VERIFY_MAC;
	cmd.hdr.size = sizeof(struct she_cmd_verify_mac) / sizeof(uint32_t);
	cmd.hdr.ver = MESSAGING_VERSION_2;

	cmd.key_id = key_id;
	cmd.data_length = message_length;
	cmd.data_offset = she_platform_shared_buf_offset(hdl) + 0x00;
	cmd.mac_offset = she_platform_shared_buf_offset(hdl) + message_length;
	cmd.mac_length = mac_length;

	len = she_platform_send_mu_message(hdl, (char *)&cmd, sizeof(struct she_cmd_verify_mac));
	if (len != sizeof(struct she_cmd_verify_mac)) {
		*verification_status = SHE_MAC_VERIFICATION_FAILED;
		return ERC_GENERAL_ERROR;
	}

	/* Read the response. */
	len = she_platform_read_mu_message(hdl, (char *)&rsp, sizeof(struct she_rsp_verify_mac));
	if (len != sizeof(struct she_rsp_verify_mac)) {
		printf("she_cmd_verify_mac read len:0x%x\n", len);
		*verification_status = SHE_MAC_VERIFICATION_FAILED;
		return ERC_GENERAL_ERROR;
	}

	if (rsp.rsp_code != AHAB_SUCCESS_IND) {
		printf("she_cmd_verify_mac response error:0x%x\n", rsp.rsp_code);

		*verification_status = SHE_MAC_VERIFICATION_FAILED;
		// TODO: map Seco error codes to SHE errors
		return ERC_GENERAL_ERROR;
	}

	*verification_status = (rsp.verification_status == 0 ? SHE_MAC_VERIFICATION_SUCCESS : SHE_MAC_VERIFICATION_FAILED);

	return ERC_NO_ERROR;

}
