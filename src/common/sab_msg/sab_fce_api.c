/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025 NXP
 */

#include <stdio.h>
#include <string.h>

#include "sab_fce_api.h"
#include "fce_mu_regs.h"

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

int fce_push(void *mu_base, uint8_t slot)
{
	struct fce_msg msg = {0};
	int ret;

	/* message header */
	msg.version = FCE_VERSION;
	msg.size = FCE_PUSH_REQ_SZ >> 2;
	msg.tag = FCE_CMD_TAG;
	msg.command = FCE_PUSH_REQ(slot);

	ret = imx_mu_send_recv(mu_base, &msg, &msg);
	if (ret) {
		printf("Push Error 0x%x", msg.data[0]);
		return ret;
	}

	/* return request id */
	return msg.data[1];
}

int fce_get_request_status(void *mu_base, uint32_t *req_id)
{
	struct fce_msg msg = {0};
	int ret;

	/* message header */
	msg.version = FCE_VERSION;
	msg.size = FCE_GET_REQ_STATUS_SZ >> 2;
	msg.tag = FCE_CMD_TAG;
	msg.command = FCE_GET_REQ_STATUS;
	msg.data[0] = *req_id;

	ret = imx_mu_send_recv(mu_base, &msg, &msg);
	if (ret)
		printf("Session req-id: 0x%x, Err req-id: 0x%x, Err: 0x%x.\n",
		       *req_id, msg.data[1],  msg.data[0]);

	*req_id = msg.data[1];

	return msg.data[0];
}

int fce_read_clear_gsr(void *mu_base)
{
	return imx_mu_read_clear_gsr(mu_base);
}
