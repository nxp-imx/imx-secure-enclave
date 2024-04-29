// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "she_api.h"
#include "shx_test.h"
#include "shx_test_macros.h"

/* Test load plain key */
uint32_t she_test_load_plain_key(she_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;
	op_load_plain_key_args_t args = {0};

	she_err_t err = 1;

	/* read the session index. */
	uint32_t index = READ_VALUE(fp, uint32_t);
	uint32_t key_store_n = READ_VALUE(fp, uint32_t);

	/* read the key parameter */
	uint8_t *key = READ_INPUT_BUFFER(fp, 16u);  // input: 128 bits

	memcpy(args.key, key, SHE_KEY_SIZE_IN_BYTES);

	err = she_load_plain_key(testCtx[index].service_hdl[key_store_n][UTILS], &args);

	/* read the expected error code and check it. */
	READ_CHECK_VALUE(testCtx, fp, err);

	if (key)
		free(key);

	return fails;
}

/* Test export ram key */
uint32_t she_test_export_plain_key(she_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;

	she_err_t err = 1;
	she_err_t expected_err;
	op_export_plain_key_args_t args = {0};

	/* read the session index. */
	uint32_t index = READ_VALUE(fp, uint32_t);
	uint32_t key_store_n = READ_VALUE(fp, uint32_t);

	args.m1 = READ_OUTPUT_BUFFER(fp, 16u);  // input: 128 bits
	args.m2 = READ_OUTPUT_BUFFER(fp, 32u);  // input: 256 bits
	args.m3 = READ_OUTPUT_BUFFER(fp, 16u);  // input: 128 bits
	args.m4 = READ_OUTPUT_BUFFER(fp, 32u);  // output: 256 bits
	args.m5 = READ_OUTPUT_BUFFER(fp, 16u);  // output: 128 bits

	args.m1_size = 16;
	args.m2_size = 32;
	args.m3_size = 16;
	args.m4_size = 32;
	args.m5_size = 16;

	err = she_export_plain_key(testCtx[index].service_hdl[key_store_n][UTILS], &args);

	/* read the expected error code and check it. */
	READ_CHECK_VALUE(testCtx, fp, err);

	return fails;
}
