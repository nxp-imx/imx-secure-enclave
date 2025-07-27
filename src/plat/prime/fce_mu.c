/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <errno.h>

#include "fce_time.h"
#include "fce_mu_regs.h"

#define BIT(n) (1U << (n))

#define MU_SR_TE0_MASK	1UL
#define MU_SR_RF0_MASK	1UL
#define MU_GSR_SIG_FIN	1UL
#define MU_GSR_SIG_ERR	BIT(1)

int
imx_mu_read_clear_gsr(struct mu_type *base)
{
	uint32_t mask = MU_GSR_SIG_FIN;
	uint32_t val;
	uint32_t count = 10;
	int ret;

	do {
		ret = read_and_timeout_check(&base->gsr, val,
					     val & mask, 1000000);
		if (ret < 0) {
			count--;
			printf("mu read gsr wait %us\n", 10 - count);
		} else {
			break;
		}
	} while (count > 0);

	if (count == 0) {
		printf("%s timeout\n", __func__);
		return -ETIMEDOUT;
	}
	/* clear the global status register */
	*(volatile unsigned int *)&base->gsr = val;

	if (val & MU_GSR_SIG_ERR)
		return -EIO;

	return 0;
}

static int
imx_mu_read(struct mu_type *base, uint32_t reg_index, uint32_t *msg)
{
	uint32_t mask = MU_SR_RF0_MASK << reg_index;
	uint32_t val, rr_num;
	uint32_t count = 10;
	int ret;

	rr_num = ((*(volatile unsigned int *)(&base->par)) & 0xFF00) >> 8;
	if (rr_num <= reg_index)
		return -EIO;

	do {
		/* Wait RX register to be full. */
		ret = read_and_timeout_check(&base->rsr, val,
					     val & mask, 1000000);
		if (ret < 0) {
			count--;
			printf("mu receive msg wait %us\n", 10 - count);
		} else {
			break;
		}
	} while (count > 0);

	if (count == 0) {
		printf("%s timeout\n", __func__);
		return -ETIMEDOUT;
	}

	*msg = *(volatile unsigned int *)(&base->rr[reg_index]);

	return 0;
}

static int
imx_mu_rx(struct mu_type *base, void *data)
{
	struct fce_msg *msg = (struct fce_msg *)data;
	uint32_t count = 0, rr_num;
	int ret;

	if (!msg)
		return -EINVAL;

	/* Read first word */
	ret = imx_mu_read(base, 0, (uint32_t *)msg);
	if (ret)
		return ret;

	count++;

	/* Check size */
	if (msg->size > FCE_MAX_MSG) {
		*((uint32_t *)msg) = 0;
		return -EINVAL;
	}

	rr_num = ((*(volatile unsigned int *)(&base->par)) & 0xFF00) >> 8;

	/* Read remaining words */
	while (count < msg->size) {
		ret = imx_mu_read(base, count % rr_num,
				  &msg->data[count - 1]);
		if (ret)
			return ret;

		count++;
	}

	return 0;
}

static int
imx_mu_write(struct mu_type *base, uint32_t reg_index, uint32_t msg)
{
	uint32_t mask = MU_SR_TE0_MASK << reg_index;
	uint32_t val, tr_num;
	int ret;

	tr_num = (*(volatile unsigned int *)(&base->par)) & 0xFF;
	if (tr_num <= reg_index)
		return -EIO;

	/* Wait TX register to be empty. */
	ret = read_and_timeout_check(&base->tsr, val,
				     val & mask, 10000);
	if (ret < 0) {
		printf("%s timeout\n", __func__);
		return -ETIMEDOUT;
	}

	*(volatile unsigned int *)&base->tr[reg_index] = msg;

	return 0;
}

static int
imx_mu_tx(struct mu_type *base, void *data)
{
	struct fce_msg *msg = (struct fce_msg *)data;
	uint8_t count = 0, tr_num;
	int ret;

	if (!msg)
		return -EINVAL;

	/* Check size */
	if (msg->size > FCE_MAX_MSG)
		return -EINVAL;

	/* Write first word */
	ret = imx_mu_write(base, 0, *((uint32_t *)msg));
	if (ret)
		return ret;

	count++;
	tr_num = (*(volatile unsigned int *)(&base->par)) & 0xFF;

	/* Write remaining words */
	while (count < msg->size) {
		ret = imx_mu_write(base, count % tr_num,
				   msg->data[count - 1]);
		if (ret)
			return ret;

		count++;
	}

	return 0;
}

int
imx_mu_send_recv(void *mu_base, void *tx_msg, void *rx_msg)
{
	struct mu_type *base = (struct mu_type *)mu_base;
	uint32_t result;
	int ret;

	/* Expect tx_msg, rx_msg are the same value */
	if (rx_msg && tx_msg != rx_msg)
		printf("tx_msg %p, rx_msg %p\n", tx_msg, rx_msg);

	ret = imx_mu_tx(base, tx_msg);
	if (ret)
		return ret;

	ret = imx_mu_rx(base, rx_msg);
	if (ret)
		return ret;

	result = ((struct fce_msg *)rx_msg)->data[0];
	if ((result & 0xff) == REQ_SUCCESS)
		return 0;
	else if ((result & 0xffff) == FCE_FIFO_FULL)
		return -ENOSPC;

	return -EIO;
}

void
imx_mu_init(struct mu_type *base)
{
	uint32_t rr_num = ((*(volatile unsigned int *)(&base->par)) & 0xFF00) >> 8;
	uint32_t i;

	*(volatile unsigned int *)&base->tcr = 0;
	*(volatile unsigned int *)&base->rcr = 0;

	while (1) {
		/* If there is pending RX data, clear them by read them out */
		if (!((*(volatile unsigned int *)&base->sr) & (1UL << 6)))
			return;

		for (i = 0; i < rr_num; i++)
			(*(volatile unsigned int *)(&base->rr[i]));
	}
}
