// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#ifndef PRIME_MEM_H
#define PRIME_MEM_H

int prime_malloc(uint32_t service_hdl,
		 uint8_t **virt_addr,
		 uint32_t *phys_addr,
		 uint32_t len);
void prime_mfree(uint32_t service_hdl, uint32_t len);

void prime_mcopy(void *dst, void *src, size_t size);
int prime_mcompare(void *dst, void *src, size_t size);

#endif
