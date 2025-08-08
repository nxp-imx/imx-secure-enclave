// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <stdio.h>

#include "crrm_api.h"

crrm_err_t crrm_test_boot_mode(crrm_hdl_t crrm_hdl)
{
	op_get_boot_mode_args_t gargs = {0};
	crrm_err_t err;

	err = crrm_get_boot_mode(crrm_hdl, &gargs);
	printf("\nCurrent Boot mode is 0x%x\n\n", gargs.boot_mode);

	return err;
}
