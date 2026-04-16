/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2026 NXP
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

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
