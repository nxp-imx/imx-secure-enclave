// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023, 2025-2026 NXP
 */

#include "hsm_api.h"

hsm_err_t gen_rng_hex_str(hsm_hdl_t sess_hdl, op_get_random_args_t *rng_get_random_args,
			  uint8_t *rng_out_buff, bool flag_print_disabled)
{
	hsm_err_t ret;
	int j;

	memset(rng_out_buff, 0, rng_get_random_args->random_size);
	rng_get_random_args->output = rng_out_buff;

	ret = hsm_do_rng(sess_hdl, rng_get_random_args);
	if (ret != HSM_NO_ERROR) {
		printf("Error[0x%x]: Failed to generate RNG number.\n", ret);
		return ret;
	}

	if (flag_print_disabled)
		return ret;

	printf("RNG: %d bytes random data received\n", rng_get_random_args->random_size);
	for (j = 0; j < rng_get_random_args->random_size; j++)
		printf("%02x", rng_out_buff[j]);
	printf("\n");

	return ret;
}

hsm_err_t do_rng_test(hsm_hdl_t sess_hdl)
{
	op_get_random_args_t rng_get_random_args = {0};
	uint8_t rng_out_buff[4096] = {0};
	hsm_err_t ret;
	int i = 3;

	do {
		rng_get_random_args.random_size = i;
		ret = gen_rng_hex_str(sess_hdl, &rng_get_random_args,
				      rng_out_buff, false);
		if (ret) {
			printf("Error[0x%02x]: RNG test failed for size[%d bytes].",
			       ret, rng_get_random_args.random_size);
			return ret;
		}
		i = i + 1000;
	} while (i <= 4096);

	return ret;
}

