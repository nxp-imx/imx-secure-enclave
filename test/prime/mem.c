/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2026 NXP
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

int prime_mcompare(void *dst, void *src, size_t size)
{
	size_t aligned_size = 0;
	char *d8 = (char *)dst;
	char *s8 = (char *)src;
	uint32_t *d32, *s32;

	/* Fast path: Compare 16-byte aligned chunks using memcmp */
	if (((uintptr_t)src % 16) == 0 && ((uintptr_t)dst % 16) == 0) {
		aligned_size = (size / 16) * 16;
		if (aligned_size > 0) {
			if (memcmp(dst, src, aligned_size) != 0)
				return -1;
			d8  += aligned_size;
			s8  += aligned_size;
			size -= aligned_size;
		}
	}

	/* Medium path: Compare remaining 32-bit word aligned chunks */
	if (size >= sizeof(uint32_t)) {
		d32 = (uint32_t *)d8;
		s32 = (uint32_t *)s8;

		while (size >= sizeof(uint32_t)) {
			if (*d32++ != *s32++)
				return -1;
			size -= sizeof(uint32_t);
		}

		d8 = (char *)d32;
		s8 = (char *)s32;
	}

	/* Slow path: Compare remaining bytes */
	while (size--) {
		if (*d8++ != *s8++)
			return -1;
	}

	return 0;
}

void prime_mcopy(void *dst, void *src, size_t size)
{
	size_t aligned_size = 0;
	char *d8 = (char *)dst;
	char *s8 = (char *)src;
	uint32_t *d32, *s32;

	/* Fast path: Copy 16-byte aligned chunks using memcpy */
	if (((uintptr_t)src % 16) == 0 && ((uintptr_t)dst % 16) == 0) {
		aligned_size = (size / 16) * 16;
		if (aligned_size > 0) {
			memcpy(dst, src, aligned_size);
			size -= aligned_size;
		}
	}

	d8 += aligned_size;
	s8 += aligned_size;

	/* Medium path: Copy remaining 32-bit word aligned chunks */
	if (size >= sizeof(uint32_t)) {
		d32 = (uint32_t *)d8;
		s32 = (uint32_t *)s8;

		while (size >= sizeof(uint32_t)) {
			*d32++ = *s32++;
			size -= sizeof(uint32_t);
		}

		d8 = (char *)d32;
		s8 = (char *)s32;
	}

	/* Slow path: Copy remaining bytes */
	while (size--)
		*d8++ = *s8++;
}
