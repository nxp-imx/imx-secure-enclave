/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025 NXP
 */

#include <stdio.h>
#include <string.h>

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

void imx_mu_word_copy(uint32_t *buf, uint32_t *data, uint8_t size)
{
	uint8_t i;

	for (i = 0; i < size; i++)
		*((volatile uint32_t *)buf + i) = data[i];
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

int prime_get_request_status(void *mu_base, uint32_t *req_id)
{
	struct prime_msg msg = {0};
	int ret;

	/* message header */
	msg.version = PRIME_VERSION;
	msg.size = PRIME_GET_REQ_STATUS_SZ >> 2;
	msg.tag = PRIME_CMD_TAG;
	msg.command = PRIME_GET_REQ_STATUS;
	msg.data[0] = *req_id;

	ret = imx_mu_send_recv(mu_base, &msg, &msg);
	if (ret)
		printf("Session req-id: 0x%x, Err req-id: 0x%x, Err: 0x%x.\n",
		       *req_id, msg.data[1],  msg.data[0]);

	*req_id = msg.data[1];

	return msg.data[0];
}

int prime_read_clear_gsr(void *mu_base)
{
	return imx_mu_read_clear_gsr(mu_base);
}
