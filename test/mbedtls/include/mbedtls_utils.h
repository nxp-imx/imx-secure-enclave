// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */
#ifndef MBEDTLS_UTILS_H
#define MBEDTLS_UTILS_H

#include "test_common.h"

/* Extract HASH algorithm from the provided HSM algorithm */
#define HSM_HASH_ALGO_FROM_ALGO(algo) (((algo) & 0x000000FFu) | 0x02000000u)

#define FAILURE  (1)
#define SUCCESS  (0)

uint32_t my_mbedtls_ecdh(uint16_t key_size_bits, uint16_t key_type,
			 uint8_t *pub_key, uint32_t pub_key_size,
			 uint8_t *priv_key, uint32_t priv_key_size,
			 uint8_t *ecdh, uint32_t *ecdh_size);

uint32_t my_mbedtls_tls12_prf(uint32_t hsm_tls12_algo, uint8_t *secret,
			      uint32_t secret_size, const char *label,
			      uint8_t *random, uint32_t random_size,
			      uint8_t *derived_secret, uint32_t derived_secret_size);
#endif
