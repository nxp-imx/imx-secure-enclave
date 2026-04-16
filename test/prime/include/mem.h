// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#ifndef MEM_H
#define MEM_H

void prime_mcopy(void *dst, void *src, size_t size);
int prime_mcompare(void *dst, void *src, size_t size);

#endif
