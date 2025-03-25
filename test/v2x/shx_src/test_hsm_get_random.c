// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include "hsm_exec.h"
#include "shx_test_macros.h"
#include "test_hsm_get_random.h"

uint32_t test_hsm_get_random(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;

	uint32_t index;
	op_get_random_args_t args;

	index                    = READ_VALUE(fp, uint32_t);
	args.random_size         = READ_VALUE(fp, uint32_t);
	args.output              = READ_OUTPUT_BUFFER(fp, args.random_size);

	hsm_err_t err = hsm_get_random(testCtx->hdl[index], &args);

	READ_CHECK_VALUE(testCtx, fp, err);

	WRITE_NOCHECK_BUFFER(testCtx, args.output, args.random_size);

	return fails;
}

uint32_t test_hsm_get_n_random(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;

	uint32_t index;
	uint8_t number;
	op_get_random_args_t args;
	hsm_err_t err;

	index                    = READ_VALUE(fp, uint32_t);
	number                   = READ_VALUE(fp, uint32_t);
	args.random_size         = READ_VALUE(fp, uint32_t);
	args.output              = READ_OUTPUT_BUFFER(fp, args.random_size);

	for (uint8_t i = 0; i < number; i++) {
		err = hsm_get_random(testCtx->hdl[index], &args);

		if (err == HSM_NO_ERROR) {
			testCtx->rng_size[i] = args.random_size;
			testCtx->rng_addr[i] = args.output;

			WRITE_NOCHECK_BUFFER(testCtx, args.output, args.random_size);

			if (i > 0)
				for (uint8_t j = 0; j < i; j++)
					if (memcmp(testCtx->rng_addr[i],
						   testCtx->rng_addr[j],
						   testCtx->rng_size[i])) {
						slt_print(SLT_ERROR,
							  "idx [%d]==[%d] --> [FAIL]\n",
							  i, j);
						fails++;
					}
		} else {
			break;
		}
	}

	if (!fails)
		slt_print(SLT_NOTICE, "Rng Values all different --> [PASS]\n");

	READ_CHECK_VALUE(testCtx, fp, err);

	return fails;
}
