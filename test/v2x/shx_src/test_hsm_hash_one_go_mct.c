// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include "hsm_exec.h"
#include "shx_test_macros.h"
#include "test_hsm_hash_one_go_mct.h"

uint32_t test_hsm_hash_one_go_mct(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;
	uint8_t *seed;
	uint8_t *MD0, *MD1, *MD2;
	uint8_t *msg;
	uint32_t seed_size;
	uint16_t i, j, k;
	uint32_t index;

	op_hash_one_go_args_t args;

	index                    = READ_VALUE(fp, uint32_t);
	seed_size                = READ_VALUE(fp, uint32_t);
	seed                     = READ_INPUT_BUFFER(fp, seed_size);
	args.output_size         = READ_VALUE(fp, uint32_t);
	args.output              = READ_OUTPUT_BUFFER(fp, args.output_size);
	args.algo                = READ_VALUE(fp, hsm_hash_algo_t);
	args.input_size          = 3 * seed_size;

	msg = malloc(3 * seed_size);
	MD0 = malloc(seed_size);
	MD1 = malloc(seed_size);
	MD2 = malloc(seed_size);

	for (i = 0; i < 100; i++) {
		memcpy(MD0, seed, seed_size);
		memcpy(MD1, seed, seed_size);
		memcpy(MD2, seed, seed_size);

		for (j = 0; j < 1000; j++) {
			memcpy(msg, MD2, seed_size);
			memcpy(&msg[seed_size], MD1, seed_size);
			memcpy(&msg[2 * seed_size], MD0, seed_size);

			args.input = msg;

			hsm_err_t err = hsm_hash_one_go(testCtx->hdl[index], &args);

			memcpy(MD2, MD1, seed_size);
			memcpy(MD1, MD0, seed_size);
			memcpy(MD0, args.output, seed_size);
		}
		slt_print(SLT_NOTICE, "Count %d =>\n", i);
		DISPLAY_BUFFER(args.output, seed_size);

		memcpy(seed, MD0, seed_size);
	}

	FREE_BUFFER(msg);
	FREE_BUFFER(MD0);
	FREE_BUFFER(MD1);
	FREE_BUFFER(MD2);
	FREE_BUFFER(args.output);

	return fails;
}
