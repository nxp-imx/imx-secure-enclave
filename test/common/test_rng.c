// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022 NXP
 */

#include "hsm_api.h"

hsm_err_t do_rng_test(hsm_hdl_t sess_hdl)
{
	op_get_random_args_t rng_get_random_args = {0};
	uint8_t rng_out_buff[4096];
	int i = 3, j;
	hsm_err_t err;

	rng_get_random_args.output = rng_out_buff;

	do {
		rng_get_random_args.random_size = i;
		err = hsm_do_rng(sess_hdl, &rng_get_random_args);

		printf("RNG: %d bytes random data received\n", i);
		for (j = 0; j < rng_get_random_args.random_size; j++)
			printf("%02x", rng_out_buff[j]);
		printf("\n");

		memset(rng_out_buff, 0, sizeof(rng_out_buff));
		i = i + 1000;
	} while (i <= 4096);

	return err;
}
