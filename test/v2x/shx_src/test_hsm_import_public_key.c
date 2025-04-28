// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include "hsm_exec.h"
#include "shx_test_macros.h"
#include "test_hsm_import_public_key.h"

uint32_t test_hsm_import_public_key(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;

	uint32_t index;
	op_import_public_key_args_t args;
	uint32_t key_ref;

	index                    = READ_VALUE(fp, uint32_t);
	args.key_size            = READ_VALUE(fp, uint32_t);
	args.key                 = READ_INPUT_BUFFER(fp, args.key_size);
	args.key_type            = READ_VALUE(fp, hsm_key_type_t);
	args.flags               = READ_VALUE(fp, hsm_op_import_public_key_flags_t);
	//TODO commented in tests

#ifdef PUB_KEY
	hsm_err_t err = hsm_import_public_key(testCtx->hdl[index], &args);

	READ_CHECK_VALUE(testCtx, fp, err);
#endif
	if (args.key)
		free(args.key);

	return fails;
}
