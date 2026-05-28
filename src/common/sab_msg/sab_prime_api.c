/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025-2026 NXP
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>

#include "sab_prime_api.h"
#include "sab_prime_process_msg.h"
#include "mu_regs.h"
#include "uio.h"

uint32_t crc_compute(uint32_t *msg, size_t len)
{
	uint32_t nb_words = len / 4;
	uint32_t crc = 0;
	uint32_t i;

	for (i = 0; i < nb_words - 1; i++)
		crc ^= *(msg + i);

	return crc;
}

uint32_t prime_push(void *mu_base, uint8_t slot)
{
	struct prime_msg msg = {0};

	/* message header */
	PRIME_MSG_HDR_INIT(&msg, PRIME_PUSH_REQ(slot), PRIME_PUSH_REQ_SZ);

	if (imx_mu_send_recv(mu_base, &msg, &msg)) {
		printf("Push Error 0x%x\n", msg.data[0]);
		return msg.data[0];
	}

	/* return request id */
	return msg.data[1];
}

uint32_t read_req_id(void)
{
	struct uio_prime_mu *prime_mu = get_uio_prime_mu();
	volatile uint8_t *mu_buf = prime_mu->mu_buf;

	return *(uint32_t *)(mu_buf + PRIME_REQ_ID_OFFSET);
}

int prime_deq(int uio_fd)
{
	struct pollfd pfd;
	uint32_t cnt;
	uint32_t one = 1;
	int ret;

	pfd.fd = uio_fd;
	pfd.events = POLLIN;

	/* Block until UIO interrupt arrives (10 second timeout).
	 * Only one uio_fd to poll. Hence passing 1 as a second arg.
	 */
	ret = poll(&pfd, 1, TIMEOUT);

	if (ret < 0) {
		perror("poll");
		return -1;
	}

	/* consume the UIO event */
	if (read(uio_fd, &cnt, sizeof(cnt)) != sizeof(cnt)) {
		perror("read");
		return -1;
	}

	consumer_req_id_index = read_req_id();

	/* Check if consumer_req_id_index is greater than producer_req_id_index */
	if (consumer_req_id_index > producer_req_id_index) {
		printf("consumer_req_id_index (0x%x) > producer_req_id_index (0x%x)\n",
		       consumer_req_id_index, producer_req_id_index);
		ret = -1;
	} else if (consumer_req_id_index == producer_req_id_index) {
		ret = 0;
	} else {
		/* If producer_req_id_index is greater than consumer_req_id_index,
		 * it means there are still pending requests
		 */
		printf("Req till (0x%x) completed, pending requests: 0x%x\n",
		       consumer_req_id_index,
		       producer_req_id_index - consumer_req_id_index);
		ret = 0;
	}

	/* Re-enable GIER */
	if (write(uio_fd, &one, sizeof(one)) != sizeof(one)) {
		perror("write");
		ret = -1;
	}

	return ret;
}
