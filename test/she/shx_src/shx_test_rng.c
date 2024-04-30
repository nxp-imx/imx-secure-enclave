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

uint32_t she_test_rng_init(she_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;

	she_err_t err = 1;
	she_err_t expected_err;
	open_svc_rng_args_t args = {0};

	/* read the session index. */
	uint32_t index = READ_VALUE(fp, uint32_t);

	args.flags = READ_VALUE(fp, uint8_t);

	err = she_open_rng_service(testCtx[index].she_hdl, &args);

	testCtx[index].rng_hdl = args.rng_hdl;

	READ_CHECK_VALUE(testCtx, fp, err);

	return fails;
}

uint32_t she_test_extend_seed(she_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;

	she_err_t err = 1;
	she_err_t expected_err;
	op_rng_extend_seed_t args = {0};

	/* read the session index. */
	uint32_t index = READ_VALUE(fp, uint32_t);

	uint8_t *entropy = READ_INPUT_BUFFER(fp, SHE_ENTROPY_SIZE);

	memcpy(args.entropy, entropy, SHE_ENTROPY_SIZE);
	args.entropy_size = SHE_ENTROPY_SIZE;

	err = she_extend_seed(testCtx[index].rng_hdl, &args);

	READ_CHECK_VALUE(testCtx, fp, err);

	if (entropy)
		free(entropy);

	return fails;
}

uint32_t she_test_rnd(she_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;
	uint32_t size = 0;

	she_err_t err = 1;
	she_err_t expected_err;
	op_get_random_args_t args = {0};

	/* read the session index. */
	uint32_t index = READ_VALUE(fp, uint32_t);

	args.output = READ_OUTPUT_BUFFER(fp, SHE_RND_SIZE);
	args.svc_flags = READ_VALUE(fp, uint8_t);

	args.random_size = SHE_RND_SIZE;
	err = she_get_random(testCtx[index].rng_hdl, &args);

	/* Print the generated number. */
	dump_buffer(args.output, SHE_RND_SIZE);

	/* read the expected error code. */
	READ_CHECK_VALUE(testCtx, fp, err);

	return fails;
}

uint32_t she_test_rng_close(she_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;

	she_err_t err = 1;
	she_err_t expected_err;

	/* read the session index. */
	uint32_t index = READ_VALUE(fp, uint32_t);

	err = she_close_rng_service(testCtx[index].rng_hdl);

	READ_CHECK_VALUE(testCtx, fp, err);

	return fails;
}
