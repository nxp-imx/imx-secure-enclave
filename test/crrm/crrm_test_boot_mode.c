// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <stdio.h>

#include "crrm_api.h"

hsm_err_t crrm_test_boot_mode(hsm_hdl_t crrm_hdl)
{
	op_get_boot_mode_args_t gargs = {0};
	op_set_boot_mode_args_t sargs = {0};
	hsm_err_t err;

	printf("---------------------\n");
	printf("\nBOOT MODE TEST STARTED\n");
	printf("---------------------\n");

	err = crrm_get_boot_mode(crrm_hdl, &gargs);
	printf("Current Boot mode is 0x%x: %d\n", gargs.boot_mode, gargs.timer_id);

	sargs.new_boot_mode = RECOVERY_DOWNLOAD_BOOT_MODE;
	err = crrm_set_boot_mode(crrm_hdl, &sargs);
	printf("Boot mode is new : 0x%x: stored : %d\n",
	       sargs.new_boot_mode, sargs.stored_boot_mode);

	err = crrm_get_boot_mode(crrm_hdl, &gargs);
	printf("Current Boot mode is 0x%x: %d\n", gargs.boot_mode, gargs.timer_id);

	printf("---------------------\n");
	printf("\nBOOT MODE TEST FINISHED\n");
	printf("---------------------\n");
	return err;
}
