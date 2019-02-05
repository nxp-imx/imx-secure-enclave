
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
		she_platform_close_session(hdl);
		return NULL;
	}
	printf("she_open_session rsp_code:0x%x shared_buf:0x%x size:0x%x\n", rsp.rsp_code, rsp.shared_buf, rsp.shared_buf_size);

	return hdl;
};

void she_close_session(she_hdl *hdl) {
	she_platform_close_session(hdl);
}
