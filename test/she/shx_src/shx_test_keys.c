// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024-2025 NXP
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "she_api.h"
#include "shx_test.h"
#include "shx_test_macros.h"

/* Test load key */
uint32_t she_test_load_key(she_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;

	she_err_t err = 1;
	she_err_t expected_err;
	op_key_update_args_t args = {0};

	/* read the session index. */
	uint32_t index = READ_VALUE(fp, uint32_t);
	uint32_t key_store_n = READ_VALUE(fp, uint32_t);

	// These macros define buffers and use pointers so that
	// we can replace them with values, if specified
	args.key_id = READ_VALUE(fp, uint8_t);
	args.flag = READ_VALUE(fp, uint8_t);
	args.m1 = READ_INPUT_BUFFER(fp, 16u);  // input: 128 bits
	args.m2 = READ_INPUT_BUFFER(fp, 32u);  // input: 256 bits
	args.m3 = READ_INPUT_BUFFER(fp, 16u);  // input: 128 bits
	args.m4 = READ_OUTPUT_BUFFER(fp, 32u);  // output: 256 bits
	args.m5 = READ_OUTPUT_BUFFER(fp, 16u);  // output: 128 bits

	args.m1_size = 16;
	args.m2_size = 32;
	args.m3_size = 16;
	args.m4_size = 32;
	args.m5_size = 16;
	err = she_key_update(testCtx[index].service_hdl[key_store_n][UTILS], &args);

	/* read the expected error code and check it. */
	READ_CHECK_VALUE(testCtx, fp, err);

	/* read the expected buffer values */
	READ_CHECK_BUFFER(testCtx, fp, args.m4, 32u);
	READ_CHECK_BUFFER(testCtx, fp, args.m5, 16u);

	if (args.m1)
		free(args.m1);
	if (args.m2)
		free(args.m2);
	if (args.m3)
		free(args.m3);

	return fails;
}

/* Test ext load key */
uint32_t she_test_load_key_ext(she_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;

	she_err_t err = 1;
	she_err_t expected_err;
	op_key_update_ext_args_t args = {0};

	/* read the session index. */
	uint32_t index = READ_VALUE(fp, uint32_t);
	uint32_t key_store_n = READ_VALUE(fp, uint32_t);

	// These macros define buffers and use pointers so that
	// we can replace them with values, if specified
	args.key_ext = READ_VALUE(fp, uint8_t);
	args.key_id = READ_VALUE(fp, uint8_t);
	args.flags = READ_VALUE(fp, uint8_t);
	args.m1 = READ_INPUT_BUFFER(fp, 16u);  // input: 128 bits
	args.m2 = READ_INPUT_BUFFER(fp, 32u);  // input: 256 bits
	args.m3 = READ_INPUT_BUFFER(fp, 16u);  // input: 128 bits
	args.m4 = READ_OUTPUT_BUFFER(fp, 32u);  // output: 256 bits
	args.m5 = READ_OUTPUT_BUFFER(fp, 16u);  // output: 128 bits

	args.m1_size = 16;
	args.m2_size = 32;
	args.m3_size = 16;
	args.m4_size = 32;
	args.m5_size = 16;
	err = she_key_update_ext(testCtx[index].service_hdl[key_store_n][UTILS], &args);

	/* read the expected error code and check it. */
	READ_CHECK_VALUE(testCtx, fp, err);

	/* read the expected buffer values */
	READ_CHECK_BUFFER(testCtx, fp, args.m4, 32u);
	READ_CHECK_BUFFER(testCtx, fp, args.m5, 16u);

	if (args.m1)
		free(args.m1);
	if (args.m2)
		free(args.m2);
	if (args.m3)
		free(args.m3);

	return fails;
}
