// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include "hsm_exec.h"
#include "shx_test_macros.h"
#include "test_hsm_pub_key_decompression.h"

uint32_t test_hsm_pub_key_decompression(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;

	// session index.
	uint32_t index;
	op_pub_key_dec_args_t args;

	index             = READ_VALUE(fp, uint32_t);
	args.key_size     = READ_VALUE(fp, uint16_t);
	args.key          = READ_INPUT_BUFFER(fp, args.key_size);
	args.out_key_size = READ_VALUE(fp, uint16_t);
	args.out_key      = READ_OUTPUT_BUFFER(fp, args.out_key_size);
	args.key_type     = READ_VALUE(fp, hsm_key_type_t);
	args.flags        = READ_VALUE(fp, hsm_op_pub_key_dec_flags_t);
	args.reserved     = READ_VALUE(fp, uint16_t);

	hsm_err_t err = hsm_pub_key_decompression(testCtx->hdl[index], &args);

	READ_CHECK_VALUE(testCtx, fp, err);
	READ_CHECK_BUFFER(testCtx, fp, args.out_key, args.out_key_size);

	if (args.key)
		free(args.key);
	if (args.out_key)
		free(args.out_key);

	return fails;
}
