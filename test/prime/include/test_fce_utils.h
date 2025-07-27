// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#ifndef TEST_FCE_UTILS_H
#define TEST_FCE_UTILS_H

void hexdump(uint8_t buf[], uint32_t size);
void data_cache_clean(uint8_t *buf, uint32_t len, int clean_only);

#define dccivac(p)	{ asm volatile("dc civac, %0" : : "r"(p) : "memory"); }
#define dcbf(p)		{ asm volatile("dc cvac, %0" : : "r"(p) : "memory"); }

#define FCE_CACHE_LINE_SIZE	32

#endif
