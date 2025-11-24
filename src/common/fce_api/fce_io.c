/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025 NXP
 */

#include <stdio.h>
#include <errno.h>

#include "sab_fce_process_msg.h"
#include "fce_uio.h"

#define __round_mask(x, y) ((__typeof__(x))((y) - 1))
#define round_up(x, y) ((((x) - 1) | __round_mask(x, y)) + 1)

int v2x_prime_mcompare(void *dst, void *src, size_t size)
{
	char *d8 = (char *)dst;
	char *s8 = (char *)src;

	while (size--) {
		if (*d8++ != *s8++)
			return -1;
	}

	return 0;
}

void v2x_prime_mcopy(void *dst, void *src, size_t size)
{
	uint32_t *d32 = (uint32_t *)dst;
	uint32_t *s32 = (uint32_t *)src;
	char *d8 = (char *)dst;
	char *s8 = (char *)src;

	while (size >= sizeof(uint32_t)) {
		*d32++ = *s32++;
		size = size - sizeof(uint32_t);
	}

	while (size--)
		*d8++ = *s8++;
}

void v2x_prime_mfree(uint32_t len)
{
	struct uio_fce_mu *fce_mu = get_uio_fce_mu();
	struct io_mem *iomem = &fce_mu->iomem;

	iomem->pos -= round_up(len, 8u);

	if (iomem->pos < 0)
		iomem->pos = 0;
}

int v2x_prime_malloc(uint8_t **virt_addr,
		     uint32_t *phys_addr,
		     uint32_t len)
{
	struct uio_fce_mu *fce_mu = get_uio_fce_mu();
	struct io_mem *iomem = &fce_mu->iomem;

	if (iomem->pos >= iomem->size ||
	    (round_up(len, 8u) > (iomem->size - iomem->pos))) {
		printf("Not enough space in reserved memory\n");
		return -ENOMEM;
	}

	*virt_addr = iomem->virt_addr + iomem->pos;
	*phys_addr = iomem->phys_addr + iomem->pos;
	iomem->pos += round_up(len, 8u);

	return 0;
}
