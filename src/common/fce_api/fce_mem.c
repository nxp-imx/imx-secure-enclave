/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025 NXP
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "sab_fce_process_msg.h"
#include "fce_uio.h"

#define __round_mask(x, y) ((__typeof__(x))((y) - 1))
#define round_up(x, y) ((((x) - 1) | __round_mask(x, y)) + 1)

int prime_mcompare(void *dst, void *src, size_t size)
{
	char *d8 = (char *)dst;
	char *s8 = (char *)src;

	if (((uintptr_t)src % 16) == 0)
		return memcmp(dst, src, size);

	while (size--) {
		if (*d8++ != *s8++)
			return -1;
	}

	return 0;
}

void prime_mcopy(void *dst, void *src, size_t size)
{
	uint32_t *d32 = (uint32_t *)dst;
	uint32_t *s32 = (uint32_t *)src;
	char *d8 = (char *)dst;
	char *s8 = (char *)src;

	if (((uintptr_t)src % 16) == 0) {
		memcpy(dst, src, size);
		return;
	}

	while (size >= sizeof(uint32_t)) {
		*d32++ = *s32++;
		size = size - sizeof(uint32_t);
	}

	while (size--)
		*d8++ = *s8++;
}

void prime_mfree(uint32_t service_hdl, uint32_t len)
{
	struct uio_fce_mu *fce_mu = get_uio_fce_mu();
	struct io_mem *iomem = &fce_mu->iomem;

	if (iomem->pos < round_up(len, 8u)) {
		iomem->pos = 0;
		return;
	}

	iomem->pos -= round_up(len, 8u);
}

int prime_malloc(uint32_t service_hdl, uint8_t **virt_addr, uint32_t *phys_addr,
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
