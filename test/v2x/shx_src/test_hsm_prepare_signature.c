// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include "hsm_exec.h"
#include "shx_test_macros.h"
#include "test_hsm_prepare_signature.h"

uint32_t test_hsm_prepare_signature(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;
	uint32_t index;
	op_prepare_sign_args_t args;

	index = READ_VALUE(fp, uint32_t);
	args.scheme_id   = READ_VALUE(fp, hsm_signature_scheme_id_t);
	args.flags       = READ_VALUE(fp, hsm_op_prepare_signature_flags_t);
	hsm_err_t err = hsm_prepare_signature(testCtx->hdl[index], &args);

	READ_CHECK_VALUE(testCtx, fp, err);

	return fails;
}

