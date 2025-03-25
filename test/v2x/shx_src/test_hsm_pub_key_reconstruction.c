// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include "hsm_exec.h"
#include "shx_test_macros.h"
#include "test_hsm_pub_key_reconstruction.h"

uint32_t test_hsm_pub_key_reconstruction(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;
	uint32_t index;
	op_pub_key_rec_args_t args;

	index = READ_VALUE(fp, uint32_t);
	args.pub_rec_size = READ_VALUE(fp, uint16_t);
	args.pub_rec      = READ_INPUT_BUFFER(fp, args.pub_rec_size);
	args.hash_size    = READ_VALUE(fp, uint16_t);
	args.hash         = READ_INPUT_BUFFER(fp, args.hash_size);
	args.ca_key_size  = READ_VALUE(fp, uint16_t);
	args.ca_key       = READ_INPUT_BUFFER(fp, args.pub_rec_size);
	args.out_key_size = READ_VALUE(fp, uint16_t);
	args.out_key      = READ_INPUT_BUFFER(fp, args.out_key_size);
	args.key_type     = READ_VALUE(fp, hsm_key_type_t);
	args.flags        = READ_VALUE(fp, hsm_op_pub_key_rec_flags_t);
	args.reserved     = READ_VALUE(fp, uint16_t);
	hsm_err_t err = hsm_pub_key_reconstruction(testCtx->hdl[index], &args);

	READ_CHECK_VALUE(testCtx, fp, err);
	if (err == HSM_NO_ERROR)
		READ_CHECK_BUFFER(testCtx, fp, args.out_key, args.out_key_size);

	if (args.pub_rec)
		free(args.pub_rec);
	if (args.hash)
		free(args.hash);
	if (args.ca_key)
		free(args.ca_key);
	if (args.out_key)
		free(args.out_key);

	return fails;
}
