// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024-2025 NXP
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

/* Test CMAC Open */
uint32_t she_test_open_cmac_session(she_test_struct_t *testCtx, FILE *fp)
{
	open_svc_mac_args_t args;
	uint32_t fails = 0;

	she_err_t err = 1;
	she_err_t expected_err;
	/* read the session index. */
	uint32_t index = READ_VALUE(fp, uint32_t);
	uint32_t key_store_n = READ_VALUE(fp, uint32_t);

	err = she_open_mac_service
		(testCtx[index].service_hdl[key_store_n][KEY_STORE], &args);

	/* read the expected error code and check it. */
	READ_CHECK_VALUE(testCtx[index], fp, err);

	if (!fails)
		testCtx[index].service_hdl[key_store_n][CMAC] = args.mac_serv_hdl;

	return fails;
}

/* Test CMAC close */
uint32_t she_test_close_cmac_session(she_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;
	she_err_t err = 1;
	she_err_t expected_err;

	/* read the session index. */
	uint32_t index = READ_VALUE(fp, uint32_t);
	uint32_t key_store_n = READ_VALUE(fp, uint32_t);

	err = she_close_mac_service
		(testCtx[index].service_hdl[key_store_n][CMAC]);

	/* Reset the hdl to avoid double close. */
	testCtx[index].service_hdl[key_store_n][CMAC] = 0;

	/* read the expected error code and check it. */
	READ_CHECK_VALUE(testCtx[index], fp, err);

	return fails;
}

/* Test CMAC generation command. */
uint32_t she_test_cmac_gen(she_test_struct_t *testCtx, FILE *fp)
{
	op_mac_one_go_args_t args = {0};
	she_mac_verification_status_t status;
	uint32_t fails = 0;
	she_err_t err = 1;
	struct timespec ts1, ts2;

	uint8_t nb_iter = READ_VALUE(fp, uint8_t);
	/* read the session index. */
	uint32_t index = READ_VALUE(fp, uint32_t);
	uint32_t store_n = READ_VALUE(fp, uint32_t);

	args.key_identifier = READ_VALUE(fp, uint32_t);
	args.algorithm = READ_VALUE(fp, uint8_t);
	args.payload_size = READ_VALUE(fp, uint32_t);
	args.payload = READ_INPUT_BUFFER(fp, args.payload_size);
	args.mac_size = SHE_MAC_SIZE;
	args.mac = READ_INPUT_BUFFER(fp, SHE_MAC_SIZE);
	args.flags = MAC_OP_FLAGS_MAC_GENERATION;

	(void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts1);

	for (uint32_t i = 0; i < nb_iter; i++) {
		/* Call the API to be tested. */
		err = she_mac_one_go(testCtx[index].service_hdl[store_n][CMAC],
				     &args,
				     &status);
	}

	(void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts2);

	/* check the last result */
	READ_CHECK_VALUE(testCtx, fp, err);
	READ_CHECK_BUFFER(testCtx, fp, args.mac, SHE_MAC_SIZE);

	if (nb_iter > 1u) {
		uint32_t avg_time_us = print_perf(&ts1, &ts2, nb_iter);

		READ_CHECK_RANGE(fp, avg_time_us);
	}

	if (args.payload)
		free(args.payload);

	return fails;
}

/* Test CMAC verify command */
uint32_t she_test_cmac_verif(she_test_struct_t *testCtx, FILE *fp)
{
	op_mac_one_go_args_t args = {0};
	she_mac_verification_status_t status;
	uint32_t fails = 0;
	she_err_t err = 1;
	struct timespec ts1, ts2;
	uint32_t verif;

	uint8_t nb_iter = READ_VALUE(fp, uint8_t);
	/* read the session index. */
	uint32_t index = READ_VALUE(fp, uint32_t);
	uint32_t store_n = READ_VALUE(fp, uint32_t);

	args.key_identifier = READ_VALUE(fp, uint32_t);
	args.algorithm = READ_VALUE(fp, uint8_t);
	args.payload_size = READ_VALUE(fp, uint32_t);
	args.payload = READ_INPUT_BUFFER(fp, args.payload_size);
	args.mac_size = READ_VALUE(fp, uint16_t);
	args.mac = READ_INPUT_BUFFER(fp, args.mac_size);
	args.flags = MAC_OP_FLAGS_MAC_VERIFICATION;

	(void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts1);

	for (uint32_t i = 0; i < nb_iter; i++) {
		/* Call the API to be tested. */
		err = she_mac_one_go(testCtx[index].service_hdl[store_n][CMAC],
				     &args,
				     &status);
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

	if (args.payload)
		free(args.payload);
	if (args.mac)
		free(args.mac);

	return fails;
}
