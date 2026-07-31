// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#ifndef CACHE_H
#define CACHE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum {
	CACHE_CLEAN_ONLY,
	CACHE_CLEAN_INVALIDATE,
};

#define dccivac(p)	{ asm volatile("dc civac, %0" : : "r"(p) : "memory"); }
#define dccvac(p)	{ asm volatile("dc cvac, %0" : : "r"(p) : "memory"); }
#define dsb_sy()	{ asm volatile("dsb sy" : : : "memory"); }

#define PRIME_CACHE_LINE_SIZE 64

/**
 * data_cache_clean() - Perform data cache maintenance on a buffer
 * @buf: Virtual address of the buffer
 * @len: Length of the buffer in bytes
 * @clean_flag: If equal to:
 *  0: clean only (dc cvac) only;
 *  1: clean + invalidate (dc civac)
 *
 */
void data_cache_clean(void *buf, size_t len, int clean_flag);

#endif /* CACHE_H */
