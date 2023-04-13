// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <ele_perf.h>

uint64_t diff_microsec(struct timespec *t1, struct timespec *t2)
{
	uint64_t diff = (uint64_t)(t2->tv_sec - t1->tv_sec) *
			 1000000u + (t2->tv_nsec - t1->tv_nsec) / 1000;
	return diff;
}

void update_stats(statistics *s, struct timespec *t1, struct timespec *t2)
{
	uint64_t diff = diff_microsec(t1, t2);

	s->total_time += (float)diff;
	int64_t delta = diff - s->mean_time;

	s->no_of_ops++;
	float delta_per_op = (float)delta / s->no_of_ops;

	s->mean_time += delta_per_op;
}

float kb_per_sec(size_t size, float usec)
{
	return (1000000 / usec) * ((float)size / 1024);
}

void print_perf_data(statistics *s, uint32_t size, const char *algo,
		     uint32_t ciphertext_size)
{
	printf("%d ops %s-%d's in %.4fs(%.0fus/ops)\n", s->no_of_ops, algo, size,
	       s->total_time / 1000000, s->mean_time);
}

/**
 * cipher_algo_to_string - Return the cipher algorithm pointing by the Hexval
 *
 * @val: variable storing Hexvalue pointing to the algorithm used
 *
 * Convenience function that takes a Hexval as an argument and maps it
 * to the cipher algorithm used and returns the algorithm.
 */
const char *cipher_algo_to_string(uint32_t val)
{
	switch (val) {
	case ALGO_CIPHER_ECB_NO_PAD:
		return "AES-ECB";

	case ALGO_CIPHER_CBC_NO_PAD:
		return "AES-CBC";

	case ALGO_CIPHER_CTR:
		return "AES-CTR";

	case ALGO_CIPHER_CFB:
		return "AES-CFB";

	case ALGO_CIPHER_OFB:
		return "AES-OFB";
	default:
		return NULL;
	}
	return NULL;
}

/**
 * scheme_algo_to_string - Return the signing algorithm pointing by the Hexval
 *
 * @val: variable storing Hexvalue pointing to the algorithm used
 *
 * Convenience function that takes a Hexval as an argument and maps it
 * to the signing algorithm used and returns the algorithm.
 */
const char *scheme_algo_to_string(uint32_t val)
{
	switch (val) {
	case ALGO_ECDSA_SHA224:
	case ALGO_ECDSA_SHA256:
	case ALGO_ECDSA_SHA384:
	case ALGO_ECDSA_SHA512:
		return "ECDSA_SHA";
	default:
		return NULL;
	}
	return NULL;
}

/**
 * mac_algo_to_string - Return the mac algorithm pointing by the Hexval
 *
 * @val: variable storing Hexvalue pointing to the algorithm used
 *
 * Convenience function that takes a Hexval as an argument and maps it
 * to the mac algorithm used and returns the algorithm.
 */
const char *mac_algo_to_string(uint32_t val)
{
	switch (val) {
	case ALGO_HMAC_SHA256:
	case ALGO_HMAC_SHA384:
		return "HMAC_SHA";
	case ALGO_CMAC:
		return "CMAC";
	default:
		return NULL;
	}
}
