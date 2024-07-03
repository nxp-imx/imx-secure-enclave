// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "she_api.h"
#include "shx_test.h"
#include "shx_test_macros.h"

/* get Status test*/
uint32_t she_test_get_status(she_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;
	uint32_t status = 0;
	op_get_status_args_t args = {0};

	she_err_t err = 1;

	/* read the session index. */
	uint32_t index = READ_VALUE(fp, uint32_t);
	uint32_t key_store_n = READ_VALUE(fp, uint32_t);

	err = she_get_status(testCtx[index].service_hdl[key_store_n][UTILS], &args);

	status = args.sreg;
	READ_CHECK_VALUE(testCtx, fp, err);
	READ_CHECK_VALUE(testCtx, fp, status);
	printf("Status Regs 0x%x\n", args.sreg & 0xFF);
	printf("Status Regs 0x%x\n", args.sreg);

	return fails;
}

/* get ID test*/
uint32_t she_test_get_id(she_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;
	op_get_id_args_t args = {0};
	uint8_t *temp = NULL;

	she_err_t err = 1;

	/* read the session index. */
	uint32_t index = READ_VALUE(fp, uint32_t);
	uint32_t key_store_n = READ_VALUE(fp, uint32_t);

	uint8_t *challenge = READ_INPUT_BUFFER(fp, SHE_CHALLENGE_SIZE);

	memcpy(args.challenge, challenge, SHE_CHALLENGE_SIZE);

	/* Execute the command */
	err = she_get_id(testCtx[index].service_hdl[key_store_n][UTILS], &args);

	/* Check the results */
	READ_CHECK_VALUE(testCtx, fp, err);
	printf("ID:\n");
	dump_buffer(args.id, SHE_ID_SIZE);
	printf("MAC:\n");
	dump_buffer(args.mac, SHE_MAC_SIZE);
	printf("Status : 0x%x\n", args.sreg);

	if (challenge)
		free(challenge);

	return fails;
}

/* get Status test*/
uint32_t she_test_get_last_rating_code(she_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;

	/* read the session index. */
	uint32_t index = READ_VALUE(fp, uint32_t);

	uint32_t rating_code = she_get_last_rating_code(testCtx[index].she_hdl);

	printf("Last rating_code 0x%x\n", rating_code);

	return fails;
}

uint32_t she_test_get_info(she_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;
	op_get_info_args_t args = {0};

	she_err_t err = 1;

	/* read the session index. */
	uint32_t index = READ_VALUE(fp, uint32_t);

	err = she_get_info(testCtx[index].she_hdl, &args);

	dump_buffer(args.chip_unique_id, args.chip_unq_id_sz);
	printf("user_sab_id 0x%x\n", args.user_sab_id);
	printf("chip_monotonic_counter 0x%x\n", args.chip_monotonic_counter);
	printf("chip_life_cycle 0x%x\n", args.chip_life_cycle);
	printf("SHE version 0x%x\n", args.version);
	printf("fips_mode 0x%x\n", args.fips_mode);

	return fails;
}
