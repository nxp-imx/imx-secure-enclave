// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <stdio.h>
#include <stdlib.h>

#include "crrm_api.h"

#define TIMER_INFO_SIZE			16

// Function to print the structure members
void print_nonce_info(nonce_info *info)
{
	int i = 0;

	printf("Nonce data: ");

	for (i = 0; i < NONCE_DATA_SIZE; i++)
		printf("%2x ", info->nonce_data[i]);

	printf("\nTimer Info: ");
	printf("%s\n", info->timer_info);
}

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
