// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <stdio.h>
#include <stdlib.h>

#include "crrm_api.h"

// Function to print the structure members
void print_timer_status(AWDT_timer *status)
{
	printf("Timer Initialized: %d\n", status->initialized);
	printf("TImer Running: %d\n", status->running);
	printf("BBSM Running: %d\n", status->BBSM_running);
	printf("Current Timer Value: %d ms\n", status->curr_timer_value);
	printf("Safety Period: %d ms\n", status->safety_period);
	printf("Max Timer Value: %d ms\n", status->max_timer_value);
	printf("BBSM Timer Value: %d ms\n", status->BBSM_timer_value);
	printf("Timer Info Length: %d\n", status->timer_info_len);

	printf("Timer Info: ");
	printf("%s\n", status->timer_info);
}

hsm_err_t crrm_test_get_AWDT_status(hsm_hdl_t crrm_hdl)
{
	op_get_AWDT_status_args_t args = {0};
	hsm_err_t err;
	uint8_t status_data[AWDT_TIMER_STATUS_SIZE + TIMER_INFO_SIZE] = {0};

	args.input_size = AWDT_TIMER_STATUS_SIZE + TIMER_INFO_SIZE;
	args.addr = status_data;
	err = crrm_get_AWDT_status(crrm_hdl, &args);

	args.status = (AWDT_timer *)args.addr;
	print_timer_status(args.status);

	return err;
}
