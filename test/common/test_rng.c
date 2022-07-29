/*
 * Copyright 2022 NXP
 *
 * NXP Confidential.
 * This software is owned or controlled by NXP and may only be used strictly
 * in accordance with the applicable license terms.  By expressly accepting
 * such terms or by downloading, installing, activating and/or otherwise using
 * the software, you are agreeing that you have read, and that you agree to
 * comply with and are bound by, such license terms.  If you do not agree to be
 * bound by the applicable license terms, then you may not retain, install,
 * activate or otherwise use the software.
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
