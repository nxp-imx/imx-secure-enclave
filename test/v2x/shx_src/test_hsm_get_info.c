// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include "hsm_exec.h"
#include "shx_test_macros.h"
#include "test_hsm_get_info.h"

uint32_t test_hsm_get_info(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;
	uint32_t index;
	op_get_info_args_t args;

	index                           = READ_VALUE(fp, uint32_t);

	hsm_err_t err = hsm_get_info(testCtx->hdl[index], &args);

	slt_print(SLT_INFO, "0x%x\n", args.user_sab_id);
	dump_buffer(args.chip_unique_id, sizeof(uint64_t));
	slt_print(SLT_INFO, "0x%x\n", args.chip_monotonic_counter);
	slt_print(SLT_INFO, "0x%x\n", args.chip_life_cycle);
	slt_print(SLT_INFO, "0x%x\n", args.version);
	slt_print(SLT_INFO, "0x%x\n", args.version_ext);
	slt_print(SLT_INFO, "0x%x\n", args.fips_mode);
	READ_CHECK_VALUE(testCtx, fp, err);
	return fails;
}
