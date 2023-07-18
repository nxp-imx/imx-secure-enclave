// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <string.h>
#include "she_api.h"
#include "plat_utils.h"

she_err_t she_do_rng(she_hdl_t session_hdl,
		     op_get_random_args_t *rng_get_random_args,
		     op_rng_extend_seed_t *rng_extend_seed_args)
{
	she_err_t err;
	/* Stores the error status of the main operation.
	 */
	she_err_t op_err;
#ifndef PSA_COMPLIANT
	open_svc_rng_args_t rng_srv_args = {0};

	rng_srv_args.flags = rng_get_random_args->svc_flags;

	op_err = she_open_rng_service(session_hdl, &rng_srv_args);
	if (op_err) {
		se_err("Error[0x%x]: RNG Service Open failed.\n", op_err);
		return op_err;
	}
	op_err =  she_extend_seed(session_hdl, rng_extend_seed_args);

	if (op_err) {
		se_err("Error[0x%x]: RNG failed for extend seed.\n", op_err);
		return op_err;
	}
#endif

	op_err =  she_get_random(session_hdl, rng_get_random_args);

	if (op_err) {
		se_err("Error[0x%x]: RNG failed for size (extend_seed) =%d.\n",
		       op_err, rng_get_random_args->random_size);
		return op_err;
	}

#ifndef PSA_COMPLIANT
	err = she_close_rng_service(session_hdl);
	if (err) {
		se_err("Error[0x%x]: RNG Service Close failed.\n", err);
		if (op_err == SHE_NO_ERROR)
			op_err = err;
	}
#endif
	return op_err;
}

she_err_t do_she_rng_test(she_hdl_t session_hdl)
{
	op_get_random_args_t rng_get_random_args = {0};
	op_rng_extend_seed_t rng_extend_seed_args = {0};
	uint8_t rng_out_buff[16];
	int i = 0, j;
	she_err_t err;

	rng_get_random_args.output = rng_out_buff;
	rng_get_random_args.svc_flags = 1;

	rng_extend_seed_args.entropy[0] = 0x1234;
	rng_extend_seed_args.entropy[1] = 0x5678;
	rng_extend_seed_args.entropy[2] = 0x4321;
	rng_extend_seed_args.entropy[3] = 0x8765;

	rng_extend_seed_args.entropy_size = SHE_ENTROPY_SIZE;

	do {
		rng_get_random_args.random_size = SHE_RND_SIZE;
		err = she_do_rng(session_hdl,
				 &rng_get_random_args,
				 &rng_extend_seed_args);

		se_print("%d bytes random data received : ", SHE_RND_SIZE);
		for (j = 0; j < rng_get_random_args.random_size; j++)
			printf("%02x", rng_out_buff[j]);
		printf("\n");

		memset(rng_out_buff, 0, sizeof(rng_out_buff));
		i = i + SHE_RND_SIZE;
	} while (i <= 64);

	return err;
}
