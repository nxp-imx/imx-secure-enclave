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
#include "shx_perf.h"

/* Test MAC generation command. */
uint32_t she_test_mac_gen(she_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;
	she_err_t err = 1;
	struct timespec ts1, ts2;
	op_generate_mac_t args = {0};

	uint8_t nb_iter = READ_VALUE(fp, uint8_t);
	/* read the session index. */
	uint32_t index = READ_VALUE(fp, uint32_t);
	uint32_t store_n = READ_VALUE(fp, uint32_t);

	args.key_ext = READ_VALUE(fp, uint16_t);
	args.key_id = READ_VALUE(fp, uint16_t);
	args.message_length = READ_VALUE(fp, uint16_t);
	args.message = READ_INPUT_BUFFER(fp, args.message_length);
	args.mac = READ_OUTPUT_BUFFER(fp, SHE_MAC_SIZE);

	(void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts1);

	for (uint32_t i = 0; i < nb_iter; i++) {
		/* Call the API to be tested. */
		err = she_generate_mac(testCtx[index].service_hdl[store_n][UTILS], &args);
	}

	(void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts2);

	/* check the last result */
	READ_CHECK_VALUE(testCtx, fp, err);
	READ_CHECK_BUFFER(testCtx, fp, args.mac, SHE_MAC_SIZE);

	if (nb_iter > 1u) {
		uint32_t avg_time_us = print_perf(&ts1, &ts2, nb_iter);

		READ_CHECK_RANGE(fp, avg_time_us);
	}

	if (args.message)
		free(args.message);

	return fails;
}

/* Test MAC verify command */
uint32_t she_test_mac_verif(she_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;
	she_err_t err = 1;
	struct timespec ts1, ts2;
	op_verify_mac_t args = {0};
	uint32_t verif;

	uint8_t nb_iter = READ_VALUE(fp, uint8_t);
	/* read the session index. */
	uint32_t index = READ_VALUE(fp, uint32_t);
	uint32_t store_n = READ_VALUE(fp, uint32_t);

	args.key_ext = READ_VALUE(fp, uint16_t);
	args.key_id = READ_VALUE(fp, uint16_t);
	args.message_length = READ_VALUE(fp, uint16_t);
	args.message = READ_INPUT_BUFFER(fp, args.message_length);
	args.mac_length = READ_VALUE(fp, uint8_t);
	args.mac = READ_INPUT_BUFFER(fp, args.mac_length);

	(void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts1);

	for (uint32_t i = 0; i < nb_iter; i++) {
		/* Call the API to be tested. */
		err = she_verify_mac(testCtx[index].service_hdl[store_n][UTILS], &args);
	}

	(void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts2);

	/* check the last result */
	verif = args.verification_status;
	READ_CHECK_VALUE(testCtx, fp, err);
	READ_CHECK_VALUE(testCtx, fp, verif);

	if (nb_iter > 1u) {
		uint32_t avg_time_us = print_perf(&ts1, &ts2, nb_iter);

		READ_CHECK_RANGE(fp, avg_time_us);
	}

	if (args.message)
		free(args.message);
	if (args.mac)
		free(args.mac);

	return fails;
}

uint32_t she_test_mac_verif_bit_ext(she_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;
	she_err_t err = 1;
	struct timespec ts1, ts2;
	op_verify_mac_t args = {0};
	uint32_t verif;

	uint8_t nb_iter = READ_VALUE(fp, uint8_t);
	/* read the session index. */
	uint32_t index = READ_VALUE(fp, uint32_t);
	uint32_t store_n = READ_VALUE(fp, uint32_t);

	args.key_ext = READ_VALUE(fp, uint16_t);
	args.key_id = READ_VALUE(fp, uint16_t);
	args.mac_length_encoding = READ_VALUE(fp, uint8_t);
	args.message_length = READ_VALUE(fp, uint16_t);
	args.message = READ_INPUT_BUFFER(fp, args.message_length);
	args.mac_length = READ_VALUE(fp, uint8_t);

	if (args.mac_length)
		args.mac = READ_INPUT_BUFFER(fp, args.mac_length);
	else
		args.mac = READ_INPUT_BUFFER(fp, SHE_MAC_SIZE);

	(void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts1);

	for (uint32_t i = 0; i < nb_iter; i++) {
		/* Call the API to be tested. */
		err = she_verify_mac(testCtx[index].service_hdl[store_n][UTILS], &args);
	}

	(void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts2);

	/* check the last result */
	verif = args.verification_status;
	READ_CHECK_VALUE(testCtx, fp, err);
	READ_CHECK_VALUE(testCtx, fp, verif);

	if (err != SHE_NO_ERROR) {
		slt_print(SLT_ERROR, "error returned by the SHE 0x%x\n",
			  she_get_last_rating_code(testCtx[index].she_hdl));
	}

	if (nb_iter > 1u) {
		uint32_t avg_time_us = print_perf(&ts1, &ts2, nb_iter);

		READ_CHECK_RANGE(fp, avg_time_us);
	}

	if (args.message)
		free(args.message);
	if (args.mac)
		free(args.mac);

	return fails;
}
