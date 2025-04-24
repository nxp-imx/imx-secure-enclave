// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hsm_exec.h"
#include "shx_test_macros.h"
#include "test_hsm_data_storage_service.h"

uint32_t test_hsm_open_data_storage_service(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;

	uint32_t index, new_hdl_index;
	open_svc_data_storage_args_t args;

	index            = READ_VALUE(fp, uint32_t);
	args.flags       = READ_VALUE(fp, hsm_svc_data_storage_flags_t);
	args.reserved[0] = READ_VALUE(fp, uint8_t);
	args.reserved[1] = READ_VALUE(fp, uint8_t);
	args.reserved[2] = READ_VALUE(fp, uint8_t);
	new_hdl_index    = READ_VALUE(fp, uint32_t);

	hsm_err_t err = hsm_open_data_storage_service(testCtx->hdl[index],
						      &args,
						      &testCtx->hdl[new_hdl_index]);

	slt_print(SLT_DEBUG, "Check Error, expect ");
	READ_CHECK_VALUE(testCtx, fp, err);

	return fails;
}

uint32_t test_hsm_close_data_storage_service(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;

	// read the session index.
	uint32_t index = READ_VALUE(fp, uint32_t);

	hsm_err_t err = hsm_close_data_storage_service(testCtx->hdl[index]);

	READ_CHECK_VALUE(testCtx, fp, err);

	return fails;
}
