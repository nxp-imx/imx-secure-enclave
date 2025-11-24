/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025 NXP
 */

#include <stdio.h>
#include <string.h>

#include "sab_fce_api.h"
#include "sab_fce_service.h"
#include "fce_mu_regs.h"

int fce_service_open(void *mu_base)
{
	struct fce_msg msg = {0};
	int ret;

	/* message header */
	msg.version = FCE_VERSION;
	msg.size = FCE_SERVICE_REQ_SZ >> 2;
	msg.tag = FCE_CMD_TAG;
	msg.command = FCE_SERVICE_OPEN_REQ;

	ret = imx_mu_send_recv(mu_base, &msg, &msg);
	if (ret) {
		if (msg.data[0] == 0x1529)
			return 0;

		printf("Service Open Error 0x%x", msg.data[0]);
	}

	return ret;
}

void fce_service_close(void *mu_base)
{
	struct fce_msg msg = {0};

	/* message header */
	msg.version = FCE_VERSION;
	msg.size = FCE_SERVICE_REQ_SZ >> 2;
	msg.tag = FCE_CMD_TAG;
	msg.command = FCE_SERVICE_CLOSE_REQ;

	imx_mu_send_recv(mu_base, &msg, &msg);
}
