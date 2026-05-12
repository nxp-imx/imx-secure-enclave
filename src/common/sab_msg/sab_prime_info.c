/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2026 NXP
 */

#include <stdio.h>

#include "sab_prime_api.h"
#include "sab_prime_info.h"
#include "mu_regs.h"

int process_prime_get_info(void *mu_base, prime_info_t *prime_info)
{
	struct prime_msg msg = {0};
	int ret;
	/* message header */
	PRIME_MSG_HDR_INIT(&msg, PRIME_GET_INFO_REQ, PRIME_GET_INFO_REQ_SZ);

	ret = imx_mu_send_recv(mu_base, &msg, &msg);
	if (ret) {
		printf("Error in retrieving Prime info 0x%x", msg.data[0]);
		return ret;
	}

	prime_info->major = (msg.data[1] >> FW_MAJOR_SHIFT) & FW_VERSION_MASK;
	prime_info->minor = (msg.data[1] >> FW_MINOR_SHIFT) & FW_VERSION_MASK;
	prime_info->patch = msg.data[1] & FW_VERSION_MASK;
	prime_info->num_fifo_entries = msg.data[2];

	return ret;
}
