// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include "hsm_exec.h"
#include "shx_test_macros.h"
#include "test_hsm_hash_one_go.h"

uint32_t test_hsm_hash_one_go(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;
	uint32_t index;

	op_hash_one_go_args_t args;

	index            = READ_VALUE(fp, uint32_t);
	args.input_size  = READ_VALUE(fp, uint32_t);
	args.input       = READ_INPUT_BUFFER(fp, args.input_size);
	args.output_size = READ_VALUE(fp, uint32_t);
	args.output      = READ_OUTPUT_BUFFER(fp, args.output_size);
	args.algo        = READ_VALUE(fp, hsm_hash_algo_t);

	hsm_err_t err = hsm_hash_one_go(testCtx->hdl[index], &args);

	READ_CHECK_VALUE(testCtx, fp, err);
	READ_CHECK_BUFFER(testCtx, fp, args.output, args.output_size);

#ifdef CAVP_SUPPORT
	DISPLAY_BUFFER(args.output, args.output_size);
#endif

	FREE_BUFFER(args.input);
	FREE_BUFFER(args.output);

	return fails;
}
