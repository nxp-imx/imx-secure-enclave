// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include "internal/cache.h"

void data_cache_clean(void *buf, size_t len, int clean_flag)
{
	uintptr_t start, end, addr;

	if (!buf || !len) {
		return;
	}

	start = (uintptr_t)buf & ~(PRIME_CACHE_LINE_SIZE - 1);
	end   = ((uintptr_t)buf + len + PRIME_CACHE_LINE_SIZE - 1) &
		~(PRIME_CACHE_LINE_SIZE - 1);

	for (addr = start; addr < end; addr += PRIME_CACHE_LINE_SIZE) {
		if (clean_flag == CACHE_CLEAN_ONLY) {
			dccvac((void *)addr);      // DC CVAC
		} else if (clean_flag == CACHE_CLEAN_INVALIDATE) {
			dccivac((void *)addr);     // DC CIVAC
		} else {
			return;
		}

	}

	dsb_sy();
}

