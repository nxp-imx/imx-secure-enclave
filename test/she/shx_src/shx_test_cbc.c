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
#include "shx_perf.h"

/* Test CBC encryption .*/
uint32_t she_test_cbc_enc(she_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;
	she_err_t err = 1;
	struct timespec ts1, ts2;
	op_cipher_one_go_args_t args = {0};

	/* read number of iterations */
	uint8_t nb_iter = READ_VALUE(fp, uint8_t);

	/* read the session index. */
	uint32_t index = READ_VALUE(fp, uint32_t);
	uint32_t key_store_n = READ_VALUE(fp, uint32_t);

	/* read function parameters */
	args.key_identifier = READ_VALUE(fp, uint32_t);
	args.iv_size = READ_VALUE(fp, uint16_t);
	args.iv = READ_INPUT_BUFFER(fp, args.iv_size);
	args.flags = READ_VALUE(fp, uint8_t);
	args.cipher_algo = READ_VALUE(fp, uint8_t);
	args.input_size = READ_VALUE(fp, uint32_t);
	args.input = READ_INPUT_BUFFER(fp, args.input_size);
	args.output_size = READ_VALUE(fp, uint32_t);
	args.output = READ_OUTPUT_BUFFER(fp, args.output_size);

	(void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts1);

	for (uint32_t i = 0; i < nb_iter; i++) {
		/* Call the API to be tested. */
		err = she_cipher_one_go(testCtx[index].service_hdl[key_store_n][CIPHER],
					&args);
	}

	(void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts2);

	/* check the last result */
	READ_CHECK_VALUE(testCtx, fp, err);
	READ_CHECK_BUFFER(testCtx, fp, args.output, args.output_size);

	if (nb_iter > 1u) {
		uint32_t avg_time_us = print_perf(&ts1, &ts2, nb_iter);

		READ_CHECK_RANGE(fp, avg_time_us);
	}

	if (args.iv)
		free(args.iv);

	if (args.input)
		free(args.input);

	return fails;
}

/* Test CBC decryption .*/
uint32_t she_test_cbc_dec(she_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;
	she_err_t err = 1;
	struct timespec ts1, ts2;
	op_cipher_one_go_args_t args = {0};

	/* read number of iterations */
	uint8_t nb_iter = READ_VALUE(fp, uint8_t);

	/* read the session index. */
	uint32_t index = READ_VALUE(fp, uint32_t);
	uint32_t key_store_n = READ_VALUE(fp, uint32_t);

	/* read function parameters */
	args.key_identifier = READ_VALUE(fp, uint32_t);
	args.iv_size = READ_VALUE(fp, uint16_t);
	args.iv = READ_INPUT_BUFFER(fp, args.iv_size);
	args.flags = READ_VALUE(fp, uint8_t);
	args.cipher_algo = READ_VALUE(fp, uint8_t);
	args.input_size = READ_VALUE(fp, uint32_t);
	args.input = READ_INPUT_BUFFER(fp, args.input_size);
	args.output_size = READ_VALUE(fp, uint32_t);
	args.output = READ_OUTPUT_BUFFER(fp, args.output_size);

	(void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts1);

	for (uint32_t i = 0; i < nb_iter; i++) {
		/* Call the API to be tested. */
		err = she_cipher_one_go(testCtx[index].service_hdl[key_store_n][CIPHER],
					&args);
	}

	(void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts2);

	/* check the last result */
	READ_CHECK_VALUE(testCtx, fp, err);
	READ_CHECK_BUFFER(testCtx, fp, args.output, args.output_size);

	if (nb_iter > 1u) {
		uint32_t avg_time_us = print_perf(&ts1, &ts2, nb_iter);

		READ_CHECK_RANGE(fp, avg_time_us);
	}

	if (args.iv)
		free(args.iv);
	if (args.input)
		free(args.input);

	return fails;
}
