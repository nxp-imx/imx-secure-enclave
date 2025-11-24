// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#ifndef FCE_MEM_H
#define FCE_MEM_H

void v2x_prime_process_ops(uint32_t service_hdl,
			   crypto_op_args_t **ops,
			   uint32_t nb_ops);

int v2x_prime_malloc(uint32_t service_hdl,
		     uint8_t **virt_addr,
		     uint32_t *phys_addr,
		     uint32_t len);
void v2x_prime_mfree(uint32_t service_hdl, uint32_t len);

void v2x_prime_mcopy(void *dst, void *src, size_t size);
int v2x_prime_mcompare(void *dst, void *src, size_t size);

#endif
