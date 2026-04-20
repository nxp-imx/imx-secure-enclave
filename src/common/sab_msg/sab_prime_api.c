/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025-2026 NXP
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>

#include "sab_prime_api.h"
#include "mu_regs.h"

uint32_t crc_compute(uint32_t *msg, size_t len)
{
	uint32_t nb_words = len / 4;
	uint32_t crc = 0;
	uint32_t i;

	for (i = 0; i < nb_words - 1; i++)
		crc ^= *(msg + i);

	return crc;
}

int prime_push(void *mu_base, uint8_t slot)
{
	struct prime_msg msg = {0};
	int ret;

	/* message header */
	msg.version = PRIME_VERSION;
	msg.size = PRIME_PUSH_REQ_SZ >> 2;
	msg.tag = PRIME_CMD_TAG;
	msg.command = PRIME_PUSH_REQ(slot);

	ret = imx_mu_send_recv(mu_base, &msg, &msg);
	if (ret) {
		printf("Push Error 0x%x", msg.data[0]);
		return ret;
	}

	/* return request id */
	return msg.data[1];
}

int prime_deq(int uio_fd)
{
	struct pollfd pfd;
	uint32_t cnt;
	uint32_t one = 1;

	pfd.fd = uio_fd;
	pfd.events = POLLIN;

	/* Block until UIO interrupt arrives (10 second timeout).
	 * Only one uio_fd to poll. Hence passing 1 as a second arg.
	 */
	int ret = poll(&pfd, 1, TIMEOUT);

	if (ret < 0) {
		perror("poll");
		return -1;
	}

	/* consume the UIO event */
	if (read(uio_fd, &cnt, sizeof(cnt)) != sizeof(cnt)) {
		perror("read");
		return -1;
	}

	/* Re-enable GIER */
	if (write(uio_fd, &one, sizeof(one)) != sizeof(one)) {
		perror("write");
		return -1;
	}

	return 0;
}
