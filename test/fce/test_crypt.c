// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <stdio.h>
#include <stdint.h>
#include "internal/fce_service.h"

#include "include/test_fce.h"
#include "include/test_fce_utils.h"

void hexdump(uint8_t buf[], uint32_t size)
{
	int i = 0;

	for (; i < size; i++) {
		if ((i % 16) == 0)
			printf("\n");
		printf("%x ", buf[i]);
	}
	printf("\n");
}

void data_cache_clean(uint8_t *buf, uint32_t len, int clean_only)
{
	uint32_t i;

	if (clean_only) {
		for (i = 0; i <= len; i += FCE_CACHE_LINE_SIZE)
			dcbf(buf + i);
	} else {
		/* clean and invalidate */
		for (i = 0; i <= len; i += FCE_CACHE_LINE_SIZE)
			dccivac(buf + i);
	}
}

int main(void)
{
	struct fce_service_hdl_s hdl;

	v2x_prime_service_init(&hdl);

	hmac_test(hdl.service_hdl);
	aes_cbc_test(hdl.service_hdl);
	aes_ecb_test(hdl.service_hdl);
	aes_gcm_test(hdl.service_hdl);

	v2x_prime_service_deinit(&hdl);

	return 0;
}
