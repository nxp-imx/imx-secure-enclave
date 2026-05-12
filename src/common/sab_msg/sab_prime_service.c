/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025-2026 NXP
 */

#include <stdio.h>

#include "sab_prime_api.h"
#include "sab_prime_service.h"
#include "mu_regs.h"

int prime_service_open(void *mu_base)
{
	struct prime_msg msg = {0};
	int ret;

	/* message header */
	PRIME_MSG_HDR_INIT(&msg, PRIME_SERVICE_OPEN_REQ, PRIME_SERVICE_REQ_SZ);

	ret = imx_mu_send_recv(mu_base, &msg, &msg);
	if (ret) {
		if (msg.data[0] == 0x1529)
			return 0;

		printf("Service Open Error 0x%x", msg.data[0]);
	}

	return ret;
}

void prime_service_close(void *mu_base)
{
	struct prime_msg msg = {0};

	/* message header */
	PRIME_MSG_HDR_INIT(&msg, PRIME_SERVICE_CLOSE_REQ, PRIME_SERVICE_REQ_SZ);

	imx_mu_send_recv(mu_base, &msg, &msg);
}
