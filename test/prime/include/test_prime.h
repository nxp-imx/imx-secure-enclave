// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025-2026 NXP
 */

#ifndef TEST_PRIME_H
#define TEST_PRIME_H

int hmac_test(prime_hdl_t service_hdl, void *va, uint64_t phys);
int aes_cbc_test(prime_hdl_t service_hdl, void *va, uint64_t phys);
int aes_ecb_test(prime_hdl_t service_hdl, void *va, uint64_t phys);
int aes_ctr_test(prime_hdl_t service_hdl, void *va, uint64_t phys);
int aes_gcm_test(prime_hdl_t service_hdl, void *va, uint64_t phys);

int test_hmac_keyslot(prime_hdl_t service_hdl);
int test_aes_keyslot(prime_hdl_t service_hdl);
#endif
