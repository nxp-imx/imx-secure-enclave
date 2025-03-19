// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024-2025 NXP
 */
#ifndef MBEDTLS_UTILS_H
#define MBEDTLS_UTILS_H

#include "test_common.h"

#define FAILURE  (1)
#define SUCCESS  (0)

#define HSM_HASH_ALGO_SHA_256_SIZE (32u)
#define HSM_HASH_ALGO_SHA_384_SIZE (48u)
#define HSM_HASH_ALGO_SHA_512_SIZE (64u)
#define HSM_HASH_MAX_SIZE (64u)

/* Extract HASH algorithm from the provided HSM algorithm */
#define HSM_HASH_ALGO_FROM_ALGO(algo) (((algo) & 0x000000FFu) | 0x02000000u)

uint32_t my_mbedtls_aes_cbc(uint32_t key_size_bits, uint8_t *key, uint8_t flag,
			    uint8_t *in, uint32_t in_size,
			    uint8_t *out, uint8_t *iv);

uint32_t my_mbedtls_hkdf(uint32_t hash_algo,
			 uint8_t *ikm, uint32_t ikm_size,
			 uint8_t *salt, uint32_t salt_size,
			 uint8_t *info, uint32_t info_size,
			 uint8_t *okm, uint32_t okm_size);

uint32_t my_mbedtls_hkdf_expand(uint32_t hash_algo,
				uint8_t *prk, uint32_t prk_size,
				uint8_t *fixed_info, uint32_t fixed_info_size,
				uint8_t *okm, uint32_t okm_size);

uint32_t my_mbedtls_hkdf_extract(uint32_t hash_algo,
				 uint8_t *salt, uint32_t salt_size,
				 uint8_t *ikm, uint32_t ikm_size,
				 uint8_t *prk, uint32_t prk_size);

uint32_t my_mbedtls_ecdh(uint16_t key_size_bits, uint16_t key_type,
			 uint8_t *pub_key, uint32_t pub_key_size,
			 uint8_t *priv_key, uint32_t priv_key_size,
			 uint8_t *ecdh, uint32_t *ecdh_size);

uint32_t my_mbedtls_tls12_prf(uint32_t hsm_tls12_algo, uint8_t *secret,
			      uint32_t secret_size, const char *label,
			      uint8_t *random, uint32_t random_size,
			      uint8_t *derived_secret, uint32_t derived_secret_size);
#endif
