// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include "hsm_exec.h"
#include "shx_test_macros.h"
#include "test_hsm_manage_key_group.h"

uint32_t test_hsm_manage_key_group(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;

	uint32_t index;
	op_manage_key_group_args_t args;

	index                    = READ_VALUE(fp, uint32_t);
	args.key_group           = READ_VALUE(fp, uint16_t);
	args.flags               = READ_VALUE(fp, hsm_op_manage_key_group_flags_t);

	hsm_err_t err = hsm_manage_key_group(testCtx->hdl[index], &args);

	READ_CHECK_VALUE(testCtx, fp, err);

	return fails;
}

