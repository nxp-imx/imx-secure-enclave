// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#include <stdio.h>

#ifdef PSA_COMPLIANT
#include "mbedtls_test.h"

#include <mbedtls/ssl.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>

uint32_t mbedtls_early_secret_test(void)
{
	unsigned char early_secret[PSA_HASH_MAX_SIZE];
	unsigned char binder_secret[PSA_HASH_MAX_SIZE];
	uint32_t hash_length = PSA_HASH_LENGTH(PSA_ALG_SHA_256);
	unsigned char *psk = NULL;
	uint32_t psk_length = 0;
	int ret;

	printf("-----------------------------------------------\n");
	printf("MbedTLS Early Secret test:\n");
	printf("-----------------------------------------------\n");
	memset(early_secret, 0, PSA_HASH_MAX_SIZE);
	memset(binder_secret, 0, PSA_HASH_MAX_SIZE);

	ret = mbedtls_wapi_tls13_evolve_secret(PSA_ALG_SHA_256,
					       NULL,
					       psk, psk_length,
					       early_secret);
	printf("\nmbedtls_wapi_tls13_evolve_secret ret:0x%x\n", ret);

	ret = mbedtls_wapi_tls13_derive_secret(PSA_ALG_SHA_256,
					       early_secret, hash_length,
					       "ext binder", 10,
					       context_buffer,
					       sizeof(context_buffer),
					       TEST_TLS1_3_CTX_HASHED,
					       binder_secret, hash_length);

	printf("\nmbedtls_wapi_tls13_derive_secret ret:0x%x\n", ret);
	printf("\nBinder Secret:\n");
	dump_hex(binder_secret, PSA_HASH_MAX_SIZE);
	printf("-----------------------------------------------\n");

	return 0;
}

void mbedtls_hkdf_test(void)
{
	int ret;
	uint32_t mbedtls_hash_algo = MBEDTLS_MD_SHA256;
	uint32_t ikm_size = sizeof(hkdf_sha256_ikm);
	uint8_t *ikm = (uint8_t *)hkdf_sha256_ikm;
	uint32_t salt_size = sizeof(hkdf_sha256_salt);
	uint8_t *salt = (uint8_t *)hkdf_sha256_salt;
	uint32_t info_size = sizeof(hkdf_sha256_info);
	uint8_t *info = (uint8_t *)hkdf_sha256_info;
	uint32_t okm_size = sizeof(hkdf_sha256_okm);
	uint8_t okm[okm_size];
	const mbedtls_md_info_t *md = NULL;

	printf("--------------- MbedTLS HKDF test --------------\n");
	memset(okm, 0, sizeof(okm));

	/* Set MD info */
	md = mbedtls_md_info_from_type(mbedtls_hash_algo);
	if (!md) {
		printf("%s: mbedtls_md_info_from_type failed\n", __func__);
		goto out;
	}

	/* Execute MbedTLS HKDF */
	ret = mbedtls_hkdf(md, salt, salt_size, ikm, ikm_size, info, info_size,
			   okm, okm_size);
	if (ret != 0) {
		printf("%s: mbedtls_hkdf failed 0x%x\n", __func__, ret);
		goto out;
	}

	if (memcmp(okm, (uint8_t *)hkdf_sha256_okm, okm_size)) {
		printf("%s: Expected OKM match failed\n", __func__);
		goto out;
	}

	printf("MbedTLS HKDF test: SUCCESS\n");
out:
	printf("-------------------------------------------------\n");
}

void mbedtls_tls1_3_tests(void)
{
	/* TLS 1.3 tests will be added */
	mbedtls_ssl_context ssl;

	mbedtls_ssl_init(&ssl);
	mbedtls_early_secret_test();
}
#endif
