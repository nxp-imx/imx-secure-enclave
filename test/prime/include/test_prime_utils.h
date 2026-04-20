// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025-2026 NXP
 */

#ifndef TEST_PRIME_UTILS_H
#define TEST_PRIME_UTILS_H

#ifndef __aligned
#define __aligned(x) __attribute__((__aligned__(x)))
#endif

#ifndef ALIGN_UP
#define ALIGN_UP(x, align) ({		\
	typeof(align) _align = (align);	\
	(((x) + (_align - 1)) & ~(_align - 1)); \
})
#endif

void hexdump(uint8_t buf[], uint32_t size);
void data_cache_clean(uint8_t *buf, uint32_t len, int clean_only);

#define dccivac(p)	{ asm volatile("dc civac, %0" : : "r"(p) : "memory"); }
#define dcbf(p)		{ asm volatile("dc cvac, %0" : : "r"(p) : "memory"); }

#define PRIME_CACHE_LINE_SIZE	32

#endif
