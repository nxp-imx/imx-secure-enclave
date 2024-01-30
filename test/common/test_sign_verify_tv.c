// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#include <stdio.h>

#include "common.h"
#include "hsm_api.h"
#include "test_utils_tv.h"
#include "plat_utils.h"

#ifdef ELE_PERF
#include <ele_perf.h>
#endif

static void sign_verify_test(hsm_hdl_t key_store_hdl,
			     uint32_t key_identifier,
			     uint32_t message_size,
			     uint8_t *message,
			     uint16_t signature_size,
			     uint16_t salt_len,
			     hsm_signature_scheme_id_t scheme_id,
			     hsm_op_generate_sign_flags_t sign_gen_flags,
			     hsm_op_verify_sign_flags_t sign_verify_flags,
			     hsm_pubkey_type_t pkey_type,
			     uint16_t key_size,
			     hsm_bit_key_sz_t bit_key_sz,
			     uint16_t exp_signature_size,
			     hsm_verification_status_t exp_verification_status,
			     uint32_t exp_sign_gen_rsp,
			     uint32_t exp_sign_verify_rsp,
			     int8_t *test_status)
{
	op_generate_sign_args_t sig_gen_args = {0};
	op_verify_sign_args_t sig_ver_args = {0};
	hsm_verification_status_t verification_status;
	hsm_err_t hsmret1 = HSM_GENERAL_ERROR;
	hsm_err_t hsmret2 = HSM_GENERAL_ERROR;
	uint8_t *signature = NULL;
	op_pub_key_recovery_args_t pkey_recv_args = {0};
	uint8_t *loc_pub_key = NULL;
	hsm_hdl_t hsm_session_hdl = get_hsm_session_hdl();
	*test_status = TEST_STATUS_FAILED;

	signature = (uint8_t *) malloc(signature_size*sizeof(uint8_t));

	if (signature == NULL) {
		se_info("\nError: Couldn't allocate memory for Signature\n");
		goto out;
	}

	loc_pub_key = (uint8_t *) malloc(key_size*sizeof(uint8_t));

	if (loc_pub_key == NULL) {
		se_info("\nError: Couldn't allocate memory for Key\n");
		goto out;
	}

	memset(signature, 0, signature_size);
	memset(loc_pub_key, 0, key_size);

	/* Signature Generation */
	sig_gen_args.key_identifier = key_identifier;
	sig_gen_args.message_size = message_size;
	sig_gen_args.message = message;
	sig_gen_args.signature_size = signature_size;
	sig_gen_args.signature = signature;
	sig_gen_args.scheme_id = scheme_id;
	sig_gen_args.flags = sign_gen_flags;
#ifdef PSA_COMPLIANT
	sig_gen_args.salt_len = salt_len;
#endif

#ifdef ELE_PERF
	statistics sign_gen_stats = { };
	struct timespec time_per_op_start = { }, time_per_op_end = { };
	struct timespec  perf_runtime_start = { }, perf_runtime_end = { };
	/* Retrieving the performance run time */
	time_t perf_run_time = get_ele_perf_time() * SEC_TO_MICROSEC;

	sign_gen_stats.no_of_ops = 0;
	clock_gettime(CLOCK_MONOTONIC_RAW, &perf_runtime_start);
	clock_gettime(CLOCK_MONOTONIC_RAW, &perf_runtime_end);
	/* Calculating time difference in microseconds */
	float diff = diff_microsec(&perf_runtime_start, &perf_runtime_end);
	const char *algo_name = scheme_algo_to_string(scheme_id);

	printf("Doing %s-%d signing for %lds on %d size blocks: ",
	       algo_name, bit_key_sz, get_ele_perf_time(), message_size);

	while (diff < perf_run_time) {
		/* Retrieving time before the hsm_do_sign call */
		clock_gettime(CLOCK_MONOTONIC_RAW, &time_per_op_start);
#endif
		hsmret1 = hsm_do_sign(key_store_hdl, &sig_gen_args);
#ifdef ELE_PERF
		/* Retrieving time after the hsm_do_sign call */
		clock_gettime(CLOCK_MONOTONIC_RAW, &time_per_op_end);
		/* Updating the statistics structure after the operation */
		update_stats(&sign_gen_stats, &time_per_op_start, &time_per_op_end);

		clock_gettime(CLOCK_MONOTONIC_RAW, &perf_runtime_end);
		diff = diff_microsec(&perf_runtime_start, &perf_runtime_end);

		if (hsmret1 != HSM_NO_ERROR)
			goto out;
#endif
		if (hsmret1 != exp_sign_gen_rsp)
			goto out;
#ifdef ELE_PERF
		}

	print_perf_data(&sign_gen_stats, bit_key_sz, algo_name, message_size);
#endif

#ifdef PSA_COMPLIANT
	/*
	 * The Expected Signature size value in HSM API Signature Generation op
	 * args, is only valid for cases HSM_NO_ERROR, HSM_OUT_TOO_SMALL,
	 * HSM_GENERAL_ERROR.
	 */

	if (hsmret1 == HSM_NO_ERROR || hsmret1 == HSM_OUT_TOO_SMALL ||
		hsmret1 == HSM_GENERAL_ERROR) {

		if (sig_gen_args.exp_signature_size != exp_signature_size) {
			se_info("\nEXP_SIGNATURE_SIZE didn't match API Resp Signature size(%u)\n",
				sig_gen_args.exp_signature_size);
			goto out;
		}
	}
#endif

	/* Public Key Exportation/Recovery*/
	pkey_recv_args.key_identifier = key_identifier;
	pkey_recv_args.out_key      = loc_pub_key;
	pkey_recv_args.out_key_size = key_size;

	hsmret2 = hsm_pub_key_recovery(key_store_hdl, &pkey_recv_args);
	se_info("\nhsm_pub_key_recovery ret:0x%x\n", hsmret2);

	/* Signature Verification */
	sig_ver_args.key = loc_pub_key;
	sig_ver_args.key_size = key_size;
#ifdef PSA_COMPLIANT
	sig_ver_args.key_sz = bit_key_sz;
	sig_ver_args.pkey_type = pkey_type;
	sig_ver_args.salt_len = salt_len;
#endif
	sig_ver_args.message_size = message_size;
	sig_ver_args.message = message;
	sig_ver_args.signature_size = signature_size;
	sig_ver_args.signature = signature;
	sig_ver_args.scheme_id = scheme_id;
	sig_ver_args.flags = sign_verify_flags;
#ifdef ELE_PERF
	statistics sign_ver_stats = { };

	sign_ver_stats.no_of_ops = 0;
	clock_gettime(CLOCK_MONOTONIC_RAW, &perf_runtime_start);
	clock_gettime(CLOCK_MONOTONIC_RAW, &perf_runtime_end);
	/* Calculating time difference in microseconds */
	diff = diff_microsec(&perf_runtime_start, &perf_runtime_end);

	printf("Doing %s-%d verification for %lds on %d size blocks: ",
	       algo_name, bit_key_sz, get_ele_perf_time(), message_size);

	while (diff < perf_run_time) {
		/* Retrieving time before the hsm_verify_sign call */
		clock_gettime(CLOCK_MONOTONIC_RAW, &time_per_op_start);
#endif
		hsmret2 = hsm_verify_sign(hsm_session_hdl, &sig_ver_args, &verification_status);
#ifdef ELE_PERF
		/* Retrieving time after the hsm_verify_sign call */
		clock_gettime(CLOCK_MONOTONIC_RAW, &time_per_op_end);
		/* Updating the statistics structure after the operation */
		update_stats(&sign_ver_stats, &time_per_op_start, &time_per_op_end);

		clock_gettime(CLOCK_MONOTONIC_RAW, &perf_runtime_end);
		diff = diff_microsec(&perf_runtime_start, &perf_runtime_end);

		if (hsmret2 != HSM_NO_ERROR)
			goto out;
#endif
		if (hsmret2 != exp_sign_verify_rsp)
			goto out;
#ifdef ELE_PERF
	}

	print_perf_data(&sign_ver_stats, bit_key_sz, algo_name, message_size);
#endif

	if (sig_ver_args.verification_status != exp_verification_status) {
		se_info("\nEXP_VERIFICATION_STATUS didn't match Actual status(0x%x)\n",
			sig_ver_args.verification_status);
		goto out;
	}

	*test_status = TEST_STATUS_SUCCESS;

out:
	if (signature)
		free(signature);

	if (loc_pub_key)
		free(loc_pub_key);
}

static int8_t prepare_and_run_sign_verify_test(hsm_hdl_t key_store_hdl, FILE
						*fp)
{
	hsm_err_t ret = HSM_GENERAL_ERROR;

	uint8_t req_params_n = 15;
	uint8_t input_ctr = 0;
	uint8_t invalid_read = 0;
	uint8_t call_sign_verify_test = -1;
	int8_t test_status = TEST_STATUS_FAILED;
	size_t len = 0;
	ssize_t read = 0;

	char *param_name = NULL;
	char *param_value_token = NULL;
	char *temp = NULL;
	char *line = NULL;

	uint32_t key_tv_id = 0;
	/* Signature Generation */
	uint32_t key_identifier = 0;
	uint32_t message_size = 0;
	uint8_t *message = NULL;
	uint16_t signature_size = 0;
	uint16_t salt_len = 0;
	hsm_signature_scheme_id_t scheme_id;
	hsm_op_generate_sign_flags_t sign_gen_flags;
	uint32_t exp_sign_gen_rsp = 0;
	uint16_t exp_signature_size = 0;
	/* Signature Verification */
	hsm_op_verify_sign_flags_t sign_verify_flags;
	hsm_pubkey_type_t pkey_type;
	uint16_t key_size = 0;
	hsm_bit_key_sz_t bit_key_sz;
	uint32_t exp_sign_verify_rsp = 0;
	hsm_verification_status_t exp_verification_status;

	while ((read = getline(&line, &len, fp)) != -1) {

		if (memcmp(line, "TEST_SIGN_VERIFY_END", 20) == 0) {

			if (input_ctr == req_params_n) {
				call_sign_verify_test = 1;
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

		if (strcmp(param_name, "KEY_TV_ID") == 0) {

			key_tv_id = (uint32_t)parse_param_value(param_value_token,
							param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "MESSAGE_SIZE") == 0) {

			message_size = (uint32_t)parse_param_value(param_value_token,
						param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "MESSAGE") == 0) {

			message = (uint8_t *) malloc(message_size * sizeof(uint8_t));

			if (message == NULL) {
				invalid_read = 1;
				se_info("\nError: Couldn't allocate memory for %s\n", param_name);
				break;
			}

			memset(message, 0, message_size);
			parse_param_value_buffer(fp, &message, message_size, param_name,
									&input_ctr, &invalid_read);

		} else if (strcmp(param_name, "SIGNATURE_SIZE") == 0) {

			signature_size = (uint16_t)parse_param_value(param_value_token,
							param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "SALT_LEN") == 0) {
			salt_len = (uint16_t)parse_param_value(param_value_token,
							       param_name,
							       &input_ctr,
							       &invalid_read);

		} else if (strcmp(param_name, "SCHEME_ID") == 0) {

			scheme_id = (hsm_signature_scheme_id_t)parse_param_value(param_value_token,
							param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "SIGN_GEN_FLAGS") == 0) {

			sign_gen_flags = (hsm_op_generate_sign_flags_t)parse_param_value(
								param_value_token, param_name,
								&input_ctr, &invalid_read);

		} else if (strcmp(param_name, "SIGN_VERIFY_FLAGS") == 0) {

			sign_verify_flags = (hsm_op_verify_sign_flags_t)parse_param_value(
								param_value_token, param_name,
								&input_ctr, &invalid_read);

		} else if (strcmp(param_name, "PKEY_TYPE") == 0) {

			pkey_type = (hsm_pubkey_type_t)parse_param_value(param_value_token,
							param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "KEY_SIZE") == 0) {

			key_size = (uint16_t)parse_param_value(param_value_token,
							param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "BIT_KEY_SZ") == 0) {

			bit_key_sz = (hsm_bit_key_sz_t)parse_param_value(param_value_token,
							param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "EXP_SIGNATURE_SIZE") == 0) {

			exp_signature_size = (uint16_t)parse_param_value(param_value_token,
							param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "EXP_VERIFICATION_STATUS") == 0) {

			exp_verification_status = (hsm_verification_status_t)parse_param_value(
							param_value_token, param_name,
							&input_ctr, &invalid_read);

		} else if (strcmp(param_name, "EXP_SIGN_GEN_RSP") == 0) {

			exp_sign_gen_rsp = (uint32_t)parse_param_value(param_value_token,
							param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "EXP_SIGN_VERIFY_RSP") == 0) {

			exp_sign_verify_rsp = (uint32_t)parse_param_value(param_value_token,
							param_name, &input_ctr, &invalid_read);
		}

		/* Invalid value for any param. */
		if (invalid_read == 1)
			break;
	}

	if (call_sign_verify_test == 1) {

		se_info("Key TV ID         : %u\n", key_tv_id);
		se_info("Message Size      : %u\n", message_size);
		se_info("\nMessage           :\n");
		hexdump_bb(message, message_size);
		se_info("Signature Size    : %u\n", signature_size);
		se_info("Scheme ID         : 0x%x\n", scheme_id);
		se_info("Flags (SIGN_GEN_FLAGS)     : 0x%x\n", sign_gen_flags);
		se_info("Flags (SIGN_VERIFY_FLAGS)  : 0x%x\n", sign_verify_flags);
		se_info("Public Key Type   : 0x%x\n", pkey_type);
		se_info("Key Size          : %u\n", key_size);
		se_info("Bit Key Size      : %u\n", bit_key_sz);
		se_info("Expected Signature Size   : %u\n", exp_signature_size);
		se_info("Expected Verification Status  : 0x%x\n", exp_verification_status);
		se_info("Expected Sign Generation Resp   : 0x%x\n", exp_sign_gen_rsp);
		se_info("Expected Sign Verification Resp : 0x%x\n", exp_sign_verify_rsp);

		se_info("----------------------------------------------------\n");

		key_identifier = get_test_key_identifier(key_tv_id);

		sign_verify_test(key_store_hdl, key_identifier, message_size,
				 message, signature_size, salt_len,
				 scheme_id, sign_gen_flags, sign_verify_flags,
				 pkey_type, key_size, bit_key_sz,
				 exp_signature_size, exp_verification_status,
				 exp_sign_gen_rsp, exp_sign_verify_rsp,
				 &test_status);
	}

	if (invalid_read == 1 || read == -1) {
		test_status = TEST_STATUS_INVALID;

		/* EOF encountered before reading all param values. */
		if (read == -1)
			se_info("\nEOF reached. TEST_SIGN_VERIFY_END not detected.\n");

		se_info("\nSkipping this Test Case\n");
	}

	if (message)
		free(message);

	if (line)
		free(line);

	return test_status;
}

void sign_verify_test_tv(hsm_hdl_t key_store_hdl, FILE *fp, char *line,
			 uint8_t *tests_passed, uint8_t *tests_failed,
			 uint8_t *tests_invalid, uint8_t *tests_total)
{
	int8_t test_status = TEST_STATUS_FAILED;
	static uint8_t tsign_verify_passed;
	static uint8_t tsign_verify_failed;
	static uint8_t tsign_verify_invalids;
	static uint8_t tsign_verify_total;

#ifndef ELE_PERF
	int len = strlen(line);
	char *test_id = (char *)malloc(len * sizeof(char));

	strncpy(test_id, line, len);
	test_id[len - 1] = '\0';
#endif
	++tsign_verify_total;
	++(*tests_total);

	se_info("\n-----------------------------------------------\n");
	se_info("%s", line);
	se_info("-----------------------------------------------\n");

#ifdef PSA_COMPLIANT
	if (memcmp(line, "TEST_SIGN_VERIFY_PSA", 20) != 0) {
		se_info("Skipping Test: Test Case is NOT PSA_COMPLIANT\n");
		goto out;
	}
#else
	if (memcmp(line, "TEST_SIGN_VERIFY_NON_PSA", 24) != 0) {
		se_info("Skipping Test: Test Case is PSA_COMPLIANT\n");
		goto out;
	}
#endif
	test_status = prepare_and_run_sign_verify_test(key_store_hdl, fp);

	if (test_status == TEST_STATUS_SUCCESS) {
		se_info("\nTEST RESULT: SUCCESS\n");
		++tsign_verify_passed;
		++(*tests_passed);
#ifndef ELE_PERF
		printf("%s: SUCCESS\n", test_id);
#endif
	} else if (test_status == TEST_STATUS_FAILED) {
		se_info("\nTEST RESULT: FAILED\n");
		++tsign_verify_failed;
		++(*tests_failed);
#ifndef ELE_PERF
		printf("%s: FAILED\n", test_id);
#endif
	} else if (test_status == TEST_STATUS_INVALID) {
		se_info("\nTEST RESULT: INVALID\n");
		++tsign_verify_invalids;
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
	se_info("TSIGN_VERIFY TESTS STATUS:: TOTAL: %u, SUCCESS: %u, FAILED: %u, INVALID: %u",
		tsign_verify_total, tsign_verify_passed, tsign_verify_failed,
		tsign_verify_invalids);
	se_info("\n------------------------------------------------------------------\n\n");

}

