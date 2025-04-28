// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include "hsm_exec.h"
#include "shx_test_macros.h"
#include "test_hsm_mac_service.h"

uint32_t test_hsm_open_mac_service(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;

	uint32_t index, mac_hdl_index;
	open_svc_mac_args_t args;

	index            = READ_VALUE(fp, uint32_t);
	args.flags       = READ_VALUE(fp, hsm_svc_mac_flags_t);
	mac_hdl_index = READ_VALUE(fp, uint32_t);

	hsm_err_t err = hsm_open_mac_service(testCtx->hdl[index],
					     &args, &testCtx->hdl[mac_hdl_index]);

	slt_print(SLT_DEBUG, "Check Error, expect ");
	READ_CHECK_VALUE(testCtx, fp, err);
	slt_print(SLT_DEBUG, "Check Pointer - ");
	READ_CHECK_POINTER(testCtx, fp, testCtx->hdl[mac_hdl_index]);

	return fails;
}

uint32_t test_hsm_close_mac_service(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;

	uint32_t index = READ_VALUE(fp, uint32_t);

	hsm_err_t err = hsm_close_mac_service(testCtx->hdl[index]);

	READ_CHECK_VALUE(testCtx, fp, err);

	return fails;
}

