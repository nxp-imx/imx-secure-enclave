// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include "crrm_utils.h"

hsm_err_t crrm_test_get_nonce(hsm_hdl_t crrm_hdl)
{
	op_get_nonce_args_t args = {0};
	hsm_err_t err;
	uint8_t info[NONCE_DATA_SIZE + TIMER_INFO_SIZE] = {0};

	printf("-----------------------\n");
	printf("GET NONCE TEST STARTED:\n");
	printf("-----------------------\n");

	args.nonce_size = NONCE_DATA_SIZE + TIMER_INFO_SIZE;
	args.nonce_addr = info;
	err = crrm_get_nonce(crrm_hdl, &args);

	printf("args.output_size %d\n", args.output_size);
	args.info = (nonce_info *)args.nonce_addr;
	if (!err)
		print_nonce_info(args.info);

	printf("------------------------\n");
	printf("GET NONCE TEST FINISHED:\n");
	printf("------------------------\n");

	return err;
}
