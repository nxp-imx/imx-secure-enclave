// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <stdio.h>

#include "hsm_api.h"
#include "test_utils_tv.h"
#include "plat_utils.h"
#include "common.h"

#ifdef ELE_PERF
#include <ele_perf.h>
#endif

static void mac_test(hsm_hdl_t key_store_hdl, uint32_t key_identifier,
				hsm_op_mac_one_go_algo_t mac_algo, uint32_t payload_size,
				uint8_t *payload_data, uint16_t mac_size, uint16_t exp_mac_size,
				hsm_mac_verification_status_t exp_verification_status,
				uint8_t exp_mac_gen_hsm_rsp, uint8_t exp_mac_verify_hsm_rsp,
				int8_t *test_status, uint16_t key_size)
{
	hsm_err_t hsmret1 = HSM_GENERAL_ERROR;
	hsm_err_t hsmret2 = HSM_GENERAL_ERROR;
	op_mac_one_go_args_t mac_args = {0};
	*test_status = 0;

	mac_args.key_identifier = key_identifier;
	mac_args.algorithm = mac_algo;
	mac_args.payload_size = payload_size;
	mac_args.payload = payload_data;
	mac_args.mac_size = mac_size;
	mac_args.flags = HSM_OP_MAC_ONE_GO_FLAGS_MAC_GENERATION;

	mac_args.mac  = (uint8_t *) malloc(mac_size*sizeof(uint8_t));

	if (mac_args.mac == NULL) {
		se_info("\nError: Couldn't allocate memory for MAC Data\n");
		goto out;
	}

	memset(mac_args.mac, 0, sizeof(mac_args.mac));

#ifdef ELE_PERF
	struct timespec time_per_op_start = { }, time_per_op_end = { };
	struct timespec perf_runtime_start = { }, perf_runtime_end = { };
	statistics gen_stats = { };
	const char *algo_name = mac_algo_to_string(mac_algo);
	/* Retrieving the performance run time */
	time_t perf_run_time = get_ele_perf_time() * SEC_TO_MICROSEC;

	gen_stats.no_of_ops = 0;
	clock_gettime(CLOCK_MONOTONIC_RAW, &perf_runtime_start);
	clock_gettime(CLOCK_MONOTONIC_RAW, &perf_runtime_end);
	/* Calculating time difference in microseconds */
	float diff = diff_microsec(&perf_runtime_start, &perf_runtime_end);

	printf("Doing %s-%d generation for %lds on %d size blocks: ",
	       algo_name, key_size, get_ele_perf_time(), mac_size);

	while (diff < perf_run_time) {
		/* Retrieving time before the hsm_do_mac call */
		clock_gettime(CLOCK_MONOTONIC_RAW, &time_per_op_start);
#endif
		hsmret1 = hsm_do_mac(key_store_hdl, &mac_args);
#ifdef ELE_PERF
		/* Retrieving time after the hsm_do_mac call */
		clock_gettime(CLOCK_MONOTONIC_RAW, &time_per_op_end);
		/* Updating the statistics structure after the operation */
		update_stats(&gen_stats, &time_per_op_start, &time_per_op_end);

		if (hsmret1 != HSM_NO_ERROR)
			goto out;
#endif
		if (hsmret1 != exp_mac_gen_hsm_rsp)
			goto out;
#ifdef ELE_PERF
		clock_gettime(CLOCK_MONOTONIC_RAW, &perf_runtime_end);
		diff = diff_microsec(&perf_runtime_start, &perf_runtime_end);
	}

	print_perf_data(&gen_stats, key_size, algo_name, mac_size);
#endif

#ifdef PSA_COMPLIANT
	/*
	 * The Expected output MAC size value in HSM API MAC op args, is only
	 * valid for cases HSM_NO_ERROR, HSM_OUT_TOO_SMALL, HSM_GENERAL_ERROR.
	 */

	if (hsmret1 == HSM_NO_ERROR || hsmret1 == HSM_OUT_TOO_SMALL ||
		hsmret1 == HSM_GENERAL_ERROR) {

		if (mac_args.exp_mac_size != exp_mac_size) {
			se_info("\nEXP_MAC_SIZE didn't match MAC Generation output MAC size %u\n",
				mac_args.exp_mac_size);
			goto out;
		}
	}
#endif

	mac_args.flags = HSM_OP_MAC_ONE_GO_FLAGS_MAC_VERIFICATION;

#ifdef ELE_PERF
	statistics ver_stats = { };

	ver_stats.no_of_ops = 0;
	clock_gettime(CLOCK_MONOTONIC_RAW, &perf_runtime_start);
	clock_gettime(CLOCK_MONOTONIC_RAW, &perf_runtime_end);
	/* Calculating time difference in microseconds */
	diff = diff_microsec(&perf_runtime_start, &perf_runtime_end);

	printf("Doing %s-%d verification for %lds on %d size blocks: ",
	       algo_name, key_size, get_ele_perf_time(), mac_size);

	while (diff < perf_run_time) {
		/* Retrieving time before the hsm_do_mac call */
		clock_gettime(CLOCK_MONOTONIC_RAW, &time_per_op_start);
#endif
		hsmret2 = hsm_do_mac(key_store_hdl, &mac_args);
#ifdef ELE_PERF
		/* Retrieving time after the hsm_do_mac call */
		clock_gettime(CLOCK_MONOTONIC_RAW, &time_per_op_end);
		/* Updating the statistics structure after the operation */
		update_stats(&ver_stats, &time_per_op_start, &time_per_op_end);

		if (hsmret2 != HSM_NO_ERROR)
			goto out;

#endif
		if (hsmret2 != exp_mac_verify_hsm_rsp)
			goto out;
#ifdef ELE_PERF
		clock_gettime(CLOCK_MONOTONIC_RAW, &perf_runtime_end);
		diff = diff_microsec(&perf_runtime_start, &perf_runtime_end);
	}

	print_perf_data(&ver_stats, key_size, algo_name, mac_size);
#endif

	if ((mac_args.flags == HSM_OP_MAC_ONE_GO_FLAGS_MAC_VERIFICATION) &&
		(mac_args.verification_status != exp_verification_status)) {

		se_info("\nEXP_VERIFICATION_STATUS didn't match Actual status(0x%x)\n",
			mac_args.verification_status);
		goto out;
	}

	*test_status = 1;
out:
	if (mac_args.mac)
		free(mac_args.mac);
}

static int8_t prepare_and_run_mac_test(hsm_hdl_t key_store_hdl, FILE *fp)
{
	hsm_hdl_t key_mgmt_hdl = 0;

	uint8_t req_params_n = 10;
	uint8_t input_ctr = 0;
	uint8_t invalid_read = 0;
	uint8_t call_mac_test = -1;
	int8_t test_status = 0; /* 0 -> FAILED, 1 -> PASSED, -1 -> INVALID*/
	size_t len = 0;
	ssize_t read = 0;

	char *param_name = NULL;
	char *param_value_token = NULL;
	char *temp = NULL;
	char *line = NULL;

	uint32_t key_mgmt_tv_id = 0;
	uint32_t key_tv_id = 0;
	uint32_t key_identifier = 0;
	hsm_op_mac_one_go_algo_t mac_algo;
	uint32_t payload_size = 0;
	uint16_t mac_size = 0;
	uint8_t *payload_data = NULL;
	uint16_t exp_mac_size = 0;
	hsm_mac_verification_status_t exp_verification_status;
	uint8_t exp_mac_gen_hsm_rsp = 0;
	uint8_t exp_mac_verify_hsm_rsp = 0;
	uint32_t key_size = 0;

	while ((read = getline(&line, &len, fp)) != -1) {

		if (memcmp(line, "TEST_MAC_END", 12) == 0) {

			if (input_ctr == req_params_n) {
				call_mac_test = 1;
			} else {
				/* Invalid Test case due to less no. of params than required*/
				invalid_read = 1;
				se_info("Failed to read all required params (%u/%u)\n",
					input_ctr, req_params_n);
			}

			break;
		}

		/* Tokenizing param_name and param_value_token from line.*/
		param_name = strtok_r(line, " ", &temp);

		if (param_name == NULL) {
			continue;
		} else {
			param_value_token = strtok_r(NULL, " ", &temp);

			if (param_value_token == NULL)
				continue;
		}

		if (strcmp(param_name, "KEY_MGMT_TV_ID") == 0) {

			key_mgmt_tv_id = (uint32_t)parse_param_value(param_value_token,
							param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "KEY_TV_ID") == 0) {

			key_tv_id = (uint32_t)parse_param_value(param_value_token,
							param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "MAC_ALGO") == 0) {

			mac_algo = (hsm_op_mac_one_go_algo_t)parse_param_value(
					param_value_token, param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "PAYLOAD_SIZE") == 0) {

			payload_size = (uint32_t)parse_param_value(param_value_token,
						param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "PAYLOAD_DATA") == 0) {

			payload_data = (uint8_t *) malloc(payload_size * sizeof(uint8_t));

			if (payload_data == NULL) {
				invalid_read = 1;
				se_info("\nError: Couldn't allocate memory for %s\n", param_name);
				break;
			}

			parse_param_value_buffer(fp, &payload_data, payload_size, param_name,
									&input_ctr, &invalid_read);

		} else if (strcmp(param_name, "MAC_SIZE") == 0) {

			mac_size = (uint16_t)parse_param_value(param_value_token,
							param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "EXP_MAC_SIZE") == 0) {

			exp_mac_size = (uint16_t)parse_param_value(param_value_token,
							param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "EXP_VERIFICATION_STATUS") == 0) {

			exp_verification_status = (hsm_mac_verification_status_t)
							parse_param_value(param_value_token,
							param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "EXP_MAC_GEN_HSM_RESP") == 0) {

			exp_mac_gen_hsm_rsp  = (uint8_t)parse_param_value(param_value_token,
							param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "EXP_MAC_VERIFY_HSM_RESP") == 0) {

			exp_mac_verify_hsm_rsp  = (uint8_t)parse_param_value(param_value_token,
							param_name, &input_ctr, &invalid_read);

		}

		/* Invalid value for any param. */
		if (invalid_read == 1)
			break;
	}

	if (call_mac_test == 1) {

		se_info("Key MGMT TV ID    : %u\n", key_mgmt_tv_id);
		se_info("Key TV ID         : %u\n", key_tv_id);
		se_info("MAC Algo          : 0x%x\n", mac_algo);
		se_info("Payload Size      : %u\n", payload_size);
		se_info("\nPayload Data      :\n");
		hexdump_bb(payload_data, payload_size);
		se_info("MAC Size          : %u\n", mac_size);
		se_info("Expected MAC Size : %u\n", exp_mac_size);
		se_info("Expected Verification Status : 0x%x\n", exp_verification_status);
		se_info("Expected MAC GEN HSM Resp    : 0x%x\n", exp_mac_gen_hsm_rsp);
		se_info("Expected MAC VERIFY HSM Resp : 0x%x\n", exp_mac_verify_hsm_rsp);

		se_info("----------------------------------------------------\n");

		key_mgmt_hdl = get_key_mgmt_hdl(key_mgmt_tv_id);
		key_identifier = get_test_key_identifier(key_tv_id);
		key_size =  get_test_key_size(key_tv_id);

		mac_test(key_store_hdl, key_identifier, mac_algo, payload_size,
				payload_data, mac_size, exp_mac_size, exp_verification_status,
				exp_mac_gen_hsm_rsp, exp_mac_verify_hsm_rsp, &test_status,
				 key_size);
	}

	if (invalid_read == 1 || read == -1) {
		test_status = -1;

		/* EOF encountered before reading all param values. */
		if (read == -1)
			se_info("\nEOF reached. TEST_MAC_END not detected.\n");

		se_info("\nSkipping this Test Case\n");
	}

	if (payload_data)
		free(payload_data);

	if (line)
		free(line);

	return test_status;
}

void mac_test_tv(hsm_hdl_t key_store_hdl, FILE *fp, char *line, uint8_t *tests_passed,
		 uint8_t *tests_failed, uint8_t *tests_invalid, uint8_t *tests_total)
{
	int8_t test_status = 0;
	static uint8_t tmac_passed;
	static uint8_t tmac_failed;
	static uint8_t tmac_invalids;
	static uint8_t tmac_total;
#ifndef ELE_PERF
	int len = strlen(line);
	char *test_id = (char *)malloc(len * sizeof(char));

	strncpy(test_id, line, len);
	test_id[len - 1] = '\0';
#endif
	++tmac_total;
	++(*tests_total);

	se_info("\n-----------------------------------------------\n");
	se_info("%s", line);
	se_info("-----------------------------------------------\n");

#ifdef PSA_COMPLIANT
	if (memcmp(line, "TEST_MAC_PSA", 12) != 0) {
		se_info("Skipping Test: Test Case is NOT PSA_COMPLIANT\n");
		goto out;
	}
#else
	if (memcmp(line, "TEST_MAC_NON_PSA", 16) != 0) {
		se_info("Skipping Test: Test Case is PSA_COMPLIANT\n");
		goto out;
	}
#endif
	test_status = prepare_and_run_mac_test(key_store_hdl, fp);

	if (test_status == 1) {
		se_info("\nTEST RESULT: SUCCESS\n");
		++tmac_passed;
		++(*tests_passed);
#ifndef ELE_PERF
		printf("%s: SUCCESS\n", test_id);
#endif
	} else if (test_status == 0) {
		se_info("\nTEST RESULT: FAILED\n");
		++tmac_failed;
		++(*tests_failed);
#ifndef ELE_PERF
		printf("%s: FAILED\n", test_id);
#endif
	} else if (test_status == -1) {
		se_info("\nTEST_RESULT: INVALID\n");
		++tmac_invalids;
		++(*tests_invalid);
#ifndef ELE_PERF
		printf("%s: INVALID\n", test_id);
#endif
	}

#ifndef ELE_PERF
	if (test_id)
		free(test_id);
#endif

out:

	se_info("\n------------------------------------------------------------------\n");
	se_info("TMAC TESTS STATUS:: TOTAL: %u, SUCCESS: %u, FAILED: %u, INVALID: %u",
		tmac_total, tmac_passed, tmac_failed, tmac_invalids);
	se_info("\n------------------------------------------------------------------\n\n");

}

