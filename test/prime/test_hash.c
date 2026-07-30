// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "prime.h"
#include "uio.h"

#include "include/mem.h"
#include "include/test_prime_utils.h"

/* Test message: "abc" */
static const uint8_t msg_abc[] = { 0x61, 0x62, 0x63 };

/* SHA2-256("abc") - NIST FIPS 180-4 */
static const uint8_t sha256_abc_ref[32] = {
	0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
	0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
	0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
	0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
};

/* SHA2-384("abc") - NIST FIPS 180-4 */
static const uint8_t sha384_abc_ref[48] = {
	0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b,
	0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50, 0x07,
	0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63,
	0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed,
	0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23,
	0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7,
};

/* SHA2-512("abc") - NIST FIPS 180-4 */
static const uint8_t sha512_abc_ref[64] = {
	0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba,
	0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
	0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
	0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
	0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8,
	0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
	0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
	0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
};

static int run_hash_test(prime_hdl_t service_hdl,
			 void *va, uint64_t phys,
			 enum crypto_hash_algorithm algo,
			 const uint8_t *msg, uint32_t msg_len,
			 const uint8_t *ref, uint32_t digest_len,
			 const char *name)
{
	hash_one_go_args_t args = {0};
	uint64_t digest_off;
	uint8_t *digest_va;
	uint64_t digest_pa;
	int err;

	/* Place input at start of shared buffer */
	prime_mcopy(va, (void *)msg, msg_len);
	data_cache_clean((uint8_t *)va, msg_len, CACHE_CLEAN_ONLY);

	/* Place digest after input, 64-byte aligned */
	digest_off = (msg_len + 63u) & ~63u;
	digest_va  = (uint8_t *)va  + digest_off;
	digest_pa  = phys           + digest_off;

	args.algo        = algo;
	args.flags       = 0;
	args.input       = (const uint8_t *)va;
	args.input_phys  = phys;
	args.input_size  = msg_len;
	args.output      = digest_va;
	args.output_phys = digest_pa;
	args.output_size = digest_len;

	err = prime_hash_one_go(service_hdl, &args);
	if (err) {
		printf("%s test: prime_hash_one_go failed (%d)\n", name, err);
		return -1;
	}

	/* Clean and invalidate cache to ensure CPU reads FCE-written result */
	data_cache_clean(digest_va, digest_len, CACHE_CLEAN_INVALIDATE);

	if (prime_mcompare(digest_va, (void *)ref, digest_len)) {
		printf("%s test FAILED\n", name);
		return -1;
	}

	printf("%s test passed\n", name);
	return 0;
}

int hash_one_go_sha256_test(prime_hdl_t service_hdl, void *va, uint64_t phys)
{
	return run_hash_test(service_hdl, va, phys,
			     CRYPTO_HASH_SHA2_256,
			     msg_abc, sizeof(msg_abc),
			     sha256_abc_ref, sizeof(sha256_abc_ref),
			     "SHA2-256 Hash-One-Go");
}

int hash_one_go_sha384_test(prime_hdl_t service_hdl, void *va, uint64_t phys)
{
	return run_hash_test(service_hdl, va, phys,
			     CRYPTO_HASH_SHA2_384,
			     msg_abc, sizeof(msg_abc),
			     sha384_abc_ref, sizeof(sha384_abc_ref),
			     "SHA2-384 Hash-One-Go");
}

int hash_one_go_sha512_test(prime_hdl_t service_hdl, void *va, uint64_t phys)
{
	return run_hash_test(service_hdl, va, phys,
			     CRYPTO_HASH_SHA2_512,
			     msg_abc, sizeof(msg_abc),
			     sha512_abc_ref, sizeof(sha512_abc_ref),
			     "SHA2-512 Hash-One-Go");
}

int hash_one_go_test(prime_hdl_t service_hdl, void *va, uint64_t phys)
{
	if (hash_one_go_sha256_test(service_hdl, va, phys))
		return -1;
	if (hash_one_go_sha384_test(service_hdl, va, phys))
		return -1;
	if (hash_one_go_sha512_test(service_hdl, va, phys))
		return -1;

	return 0;
}
