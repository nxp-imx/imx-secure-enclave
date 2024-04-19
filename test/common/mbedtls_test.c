// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#include <stdio.h>

#ifdef PSA_COMPLIANT
#include "mbedtls_test.h"

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
	printf("-----------------------------------------------\r\n");
}

void mbedtls_tls1_3_tests(void)
{
	/* TLS 1.3 tests will be added */
	mbedtls_ssl_context *ssl = NULL;

	mbedtls_ssl_init(ssl);
}
#endif
