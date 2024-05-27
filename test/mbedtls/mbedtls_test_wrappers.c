// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#ifdef PSA_COMPLIANT
#include <common.h>
#include <ssl_misc.h>
#include <ssl_tls13_keys.h>

#include "mbedtls_test.h"

/**
 * Wrapper APIs for MbedTLS library/internal functions.
 */
int mbedtls_wapi_tls13_evolve_secret(uint32_t hash_algorithm,
				     const unsigned char *in_secret,
				     const unsigned char *input_buffer,
				     size_t input_buffer_len,
				     unsigned char *out_secret)
{
	return mbedtls_ssl_tls13_evolve_secret(hash_algorithm,
					       in_secret,
					       input_buffer,
					       input_buffer_len,
					       out_secret);
}

int mbedtls_wapi_tls13_derive_secret(uint32_t hash_algorithm,
				     const unsigned char *in_secret,
				     size_t in_secret_len,
				     const unsigned char *label,
				     size_t label_length,
				     const unsigned char *context_buffer,
				     size_t context_buffer_size,
				     int context_hashed_status,
				     unsigned char *out_secret,
				     size_t out_secret_len)

{
	return mbedtls_ssl_tls13_derive_secret(hash_algorithm,
					       in_secret, in_secret_len,
					       label, label_length,
					       context_buffer, context_buffer_size,
					       context_hashed_status,
					       out_secret, out_secret_len);
}
#endif
