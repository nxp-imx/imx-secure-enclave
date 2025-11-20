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

/* Test Cipher Open */
uint32_t she_test_cipher_open(she_test_struct_t *testCtx, FILE *fp)
{
	open_svc_cipher_args_t args;
	uint32_t fails = 0;

	she_err_t err = 1;
	she_err_t expected_err;
	/* read the session index. */
	uint32_t index = READ_VALUE(fp, uint32_t);
	uint32_t key_store_n = READ_VALUE(fp, uint32_t);

	err = she_open_cipher_service
		(testCtx[index].service_hdl[key_store_n][KEY_STORE], &args);

	/* read the expected error code and check it. */
	READ_CHECK_VALUE(testCtx[index], fp, err);

	if (!fails)
		testCtx[index].service_hdl[key_store_n][CIPHER] = args.cipher_hdl;

	return fails;
}

/* Test Cipher close */
uint32_t she_test_cipher_close(she_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;
	she_err_t err = 1;
	she_err_t expected_err;

	/* read the session index. */
	uint32_t index = READ_VALUE(fp, uint32_t);
	uint32_t key_store_n = READ_VALUE(fp, uint32_t);

	err = she_close_cipher_service
		(testCtx[index].service_hdl[key_store_n][CIPHER]);

	/* Reset the hdl to avoid double close. */
	testCtx[index].service_hdl[key_store_n][CIPHER] = 0;

	/* read the expected error code and check it. */
	READ_CHECK_VALUE(testCtx[index], fp, err);

	return fails;
}

