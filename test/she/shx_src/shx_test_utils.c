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

/* Test Utils Open */
uint32_t she_test_utils_open(she_test_struct_t *testCtx, FILE *fp)
{
	op_open_utils_args_t args = {0};
	uint32_t fails = 0;

	she_err_t err = 1;
	she_err_t expected_err;
	/* read the session index. */
	uint32_t index = READ_VALUE(fp, uint32_t);
	uint32_t key_store_n = READ_VALUE(fp, uint32_t);

	err = she_open_utils(testCtx[index].service_hdl[key_store_n][KEY_STORE], &args);

	/* read the expected error code and check it. */
	READ_CHECK_VALUE(testCtx[index], fp, err);

	if (!fails)
		testCtx[index].service_hdl[key_store_n][UTILS] = args.utils_handle;

	return fails;
}

/* Test Utils close */
uint32_t she_test_utils_close(she_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;
	she_err_t err = 1;
	she_err_t expected_err;

	/* read the session index. */
	uint32_t index = READ_VALUE(fp, uint32_t);
	uint32_t key_store_n = READ_VALUE(fp, uint32_t);

	printf("0x%x\n", testCtx[index].service_hdl[key_store_n][UTILS]);

	err = she_close_utils
		(testCtx[index].service_hdl[key_store_n][UTILS]);

	/* Reset the hdl to avoid double close. */
	testCtx[index].service_hdl[key_store_n][UTILS] = 0;

	/* read the expected error code and check it. */
	READ_CHECK_VALUE(testCtx[index], fp, err);

	return fails;
}
