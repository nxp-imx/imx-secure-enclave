// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025-2026 NXP
 */

#ifndef TEST_PRIME_UTILS_H
#define TEST_PRIME_UTILS_H

#include "internal/cache.h"

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

#endif
