// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2024 NXP
 */

#include <stdio.h>
#include <string.h>

#include "hsm_api.h"
#include "test_utils_tv.h"
#include "plat_utils.h"
#include "common.h"

#ifdef ELE_PERF
#include <ele_perf.h>
#endif

static hsm_err_t cipher_test(hsm_hdl_t key_store_hdl, hsm_hdl_t key_mgmt_hdl,
				uint32_t key_identifier, hsm_op_cipher_one_go_algo_t cipher_algo,
				uint16_t iv_size, uint8_t *iv_data, uint32_t plaintext_size,
				uint8_t *input_data, uint32_t ciphertext_size,
				 uint16_t key_size)
{
	op_cipher_one_go_args_t cipher_args = {0};
	hsm_err_t hsmret = HSM_GENERAL_ERROR;
	uint8_t *ciphered_data = NULL;
	uint8_t *deciphered_data = NULL;
	hsm_hdl_t cipher_hdl = 0;

	memset(&cipher_args, 0, sizeof(cipher_args));

	ciphered_data = (uint8_t *) malloc(ciphertext_size*sizeof(uint8_t));

	if (ciphered_data == NULL) {
		se_err("\nError: Couldn't allocate memory for Ciphered Data\n");
		goto out;
	}

	deciphered_data = (uint8_t *) malloc(plaintext_size*sizeof(uint8_t));

	if (deciphered_data == NULL) {
		se_err("\nError: Couldn't allocate memory for Deciphered Data\n");
		goto out;
	}

	memset(ciphered_data, 0, sizeof(ciphered_data));
	memset(deciphered_data, 0, sizeof(deciphered_data));

	//ENCRYPT-DECRYPT common part
	cipher_args.key_identifier = key_identifier;
	cipher_args.iv = iv_data;
	cipher_args.iv_size = iv_size;
	cipher_args.cipher_algo = cipher_algo;

	//ENCRYPT
	cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_ENCRYPT;
	cipher_args.input = input_data;
	cipher_args.output = ciphered_data;
	cipher_args.input_size = plaintext_size;
	cipher_args.output_size = ciphertext_size;

#ifdef ELE_PERF
	struct timespec time_per_op_start = { }, time_per_op_end = { };
	struct timespec perf_runtime_start = { }, perf_runtime_end = { };
	statistics enc_stats = { };
	enc_stats.no_of_ops = 0;
	const char *algo_name = cipher_algo_to_string(cipher_algo);
	/* Retrieving the performance run time */
	time_t perf_run_time = get_ele_perf_time() * SEC_TO_MICROSEC;

	printf("Doing %s-%d encryption for %lds on %d size blocks: ",
	       algo_name, key_size, get_ele_perf_time(), ciphertext_size);
	clock_gettime(CLOCK_MONOTONIC_RAW, &perf_runtime_start);
	clock_gettime(CLOCK_MONOTONIC_RAW, &perf_runtime_end);
	/* Calculating time difference in microseconds */
	float diff = diff_microsec(&perf_runtime_start, &perf_runtime_end);

	while (diff < perf_run_time) {
		/* Retrieving time before the hsm_do_cipher call */
		clock_gettime(CLOCK_MONOTONIC_RAW, &time_per_op_start);
#endif
		hsmret = hsm_do_cipher(key_store_hdl, &cipher_args);
#ifdef ELE_PERF
		/* Retrieving time after the hsm_do_cipher call */
		clock_gettime(CLOCK_MONOTONIC_RAW, &time_per_op_end);
		/* Updating the statistics structure after the operation */
		update_stats(&enc_stats, &time_per_op_start, &time_per_op_end);
#endif
		if (hsmret != HSM_NO_ERROR) {
			goto out;
		}
#ifdef ELE_PERF
		clock_gettime(CLOCK_MONOTONIC_RAW, &perf_runtime_end);
		diff = diff_microsec(&perf_runtime_start, &perf_runtime_end);
	}

	print_perf_data(&enc_stats, key_size, algo_name, ciphertext_size);
#endif

#ifdef ELE_DEBUG
	se_info("\nEncrypted data:\n");
	print_buffer(ciphered_data, ciphertext_size);
#endif

	//DECRYPT
	cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_DECRYPT;
	cipher_args.input = ciphered_data;
	cipher_args.output = deciphered_data;
	cipher_args.input_size = ciphertext_size;
	cipher_args.output_size = plaintext_size;

#ifdef ELE_PERF
	statistics dec_stats = { };

	dec_stats.no_of_ops = 0;
	clock_gettime(CLOCK_MONOTONIC_RAW, &perf_runtime_start);
	clock_gettime(CLOCK_MONOTONIC_RAW, &perf_runtime_end);
	/* Calculating time difference in microseconds */
	diff = diff_microsec(&perf_runtime_start, &perf_runtime_end);

	printf("Doing %s-%d decryption for %lds on %d size blocks: ",
	       algo_name, key_size, get_ele_perf_time(), ciphertext_size);

	while (diff < perf_run_time) {
		/* Retrieving time before the hsm_do_cipher call */
		clock_gettime(CLOCK_MONOTONIC_RAW, &time_per_op_start);
#endif
		hsmret = hsm_do_cipher(key_store_hdl, &cipher_args);
#ifdef ELE_PERF
		/* Retrieving time after the hsm_do_cipher call */
		clock_gettime(CLOCK_MONOTONIC_RAW, &time_per_op_end);
		/* Updating the statistics structure after the operation */
		update_stats(&dec_stats, &time_per_op_start, &time_per_op_end);
#endif
		if (hsmret != HSM_NO_ERROR)
			goto out;
#ifdef ELE_PERF
		clock_gettime(CLOCK_MONOTONIC_RAW, &perf_runtime_end);
		diff = diff_microsec(&perf_runtime_start, &perf_runtime_end);
	}

	print_perf_data(&dec_stats, key_size, algo_name, ciphertext_size);
#endif

#ifdef ELE_DEBUG
	se_info("\nDecrypted data:\n");
	print_buffer(deciphered_data, plaintext_size);
	se_info("\n----------------------------------------------------\n");

	if (memcmp(input_data, deciphered_data, plaintext_size) == 0)
		se_info("\nDecrypted data matches Encrypted data [PASS]\n");
	else
		se_err("\nDecrypted data doesn't match Encrypted data [FAIL]\n");
#endif

out:

	if (ciphered_data)
		free(ciphered_data);

	if (deciphered_data)
		free(deciphered_data);

	return hsmret;
}

static int8_t prepare_and_run_cipher_test(hsm_hdl_t key_store_hdl, FILE *fp)
{
	hsm_err_t ret = HSM_GENERAL_ERROR;
	hsm_hdl_t key_mgmt_hdl = 0;

	uint8_t req_params_n = 9;
	uint8_t input_ctr = 0;
	uint8_t invalid_read = 0;
	uint8_t call_cipher_test = -1;
	int8_t test_status = TEST_STATUS_FAILED;
	size_t len = 0;
	ssize_t read = 0;

	char *param_name = NULL;
	char *param_value_token = NULL;
	char *temp = NULL;
	char *line = NULL;

	uint32_t key_mgmt_tv_id = 0;
	uint32_t key_tv_id = 0;
	uint32_t key_identifier = 0;
	hsm_op_cipher_one_go_algo_t cipher_algo;
	uint32_t expected_rsp_code = 0;
	uint16_t iv_size = 0;
	uint32_t input_size = 0;
	uint32_t output_size = 0;
	uint8_t *iv_data = NULL;
	uint8_t *input_data = NULL;
	uint32_t key_size = 0;

	while ((read = getline(&line, &len, fp)) != -1) {

		if (memcmp(line, "TEST_CIPHER_END", 15) == 0) {

			if (input_ctr == req_params_n) {
				call_cipher_test = 1;
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

		} else if (strcmp(param_name, "CIPHER_ALGO") == 0) {

			cipher_algo = (hsm_op_cipher_one_go_algo_t)parse_param_value(
					param_value_token, param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "IV_SIZE") == 0) {

			iv_size = (uint16_t)parse_param_value(param_value_token,
						param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "IV_DATA") == 0) {

			iv_data = (uint8_t *) malloc(iv_size * sizeof(uint8_t));

			if (iv_data == NULL) {
				invalid_read = 1;
				se_info("\nError: Couldn't allocate memory for %s\n", param_name);
				break;
			}

			parse_param_value_buffer(fp, &iv_data, iv_size, param_name,
									&input_ctr, &invalid_read);

		} else if (strcmp(param_name, "INPUT_SIZE") == 0) {

			input_size = (uint32_t)parse_param_value(param_value_token,
							param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "INPUT_DATA") == 0) {

			input_data = (uint8_t *) malloc(input_size * sizeof(uint8_t));

			if (input_data == NULL) {
				invalid_read = 1;
				se_info("\nError: Couldn't allocate memory for %s\n", param_name);
				break;
			}

			parse_param_value_buffer(fp, &input_data, input_size, param_name,
								&input_ctr, &invalid_read);

		} else if (strcmp(param_name, "OUTPUT_SIZE") == 0) {

			output_size = (uint32_t)parse_param_value(param_value_token,
							param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "EXPECTED_HSM_RESP") == 0) {

			expected_rsp_code = (uint32_t)parse_param_value(param_value_token,
							param_name, &input_ctr, &invalid_read);
		}

		/* Invalid value for any param. */
		if (invalid_read == 1)
			break;
	}

	if (call_cipher_test == 1) {
#ifdef PSA_COMPLIANT
		if (se_get_soc_id() == SOC_IMX8ULP &&
		    cipher_algo == HSM_CIPHER_ONE_GO_ALGO_OFB) {
			test_status = TEST_STATUS_SKIPPED;
			goto out;
		}
#endif
		se_info("Key MGMT TV ID    : %u\n", key_mgmt_tv_id);
		se_info("Key TV ID         : %u\n", key_tv_id);
		se_info("Cipher Algo       : 0x%x\n", cipher_algo);
		se_info("IV Size           : %u\n", iv_size);
		se_info("Input Size        : %u\n", input_size);
		se_info("Output Size       : %u\n", output_size);
		se_info("Expected HSM Resp : 0x%x\n", expected_rsp_code);
		se_info("\nIV Data           :\n");
		hexdump_bb(iv_data, iv_size);
		se_info("Input Data        :\n");
		hexdump_bb(input_data, input_size);

		se_info("----------------------------------------------------\n");

		key_mgmt_hdl = get_key_mgmt_hdl(key_mgmt_tv_id);
		key_identifier = get_test_key_identifier(key_tv_id);
		key_size =  get_test_key_size(key_tv_id);
		ret = cipher_test(key_store_hdl, key_mgmt_hdl, key_identifier,
					cipher_algo, iv_size, iv_data, input_size, input_data,
					output_size, key_size);

		if (ret == expected_rsp_code) {
			test_status = TEST_STATUS_SUCCESS;
			se_info("\nTEST RESULT: SUCCESS\n");
		} else {
			test_status = TEST_STATUS_FAILED;
			se_info("\nTEST RESULT: FAILED\n");
		}

		se_info("\ncipher_test ret: 0x%x\n", ret);
	}

	if (invalid_read == 1 || read == -1) {
		test_status = TEST_STATUS_INVALID;

		/* EOF encountered before reading all param values. */
		if (read == -1)
			se_info("\nEOF reached. TEST_CIPHER_END not detected.\n");

		se_info("\nSkipping this Test Case\n");
		se_info("\nTEST_RESULT: INVALID\n");
	}

out:
	if (iv_data)
		free(iv_data);

	if (input_data)
		free(input_data);

	if (line)
		free(line);

	return test_status;
}

void cipher_test_tv(hsm_hdl_t key_store_hdl, FILE *fp, char *line, uint8_t *tests_passed,
		    uint8_t *tests_failed, uint8_t *tests_invalid, uint8_t *tests_total)
{
	int8_t test_status = TEST_STATUS_FAILED;
	static uint8_t tcipher_passed;
	static uint8_t tcipher_failed;
	static uint8_t tcipher_invalids;
	static uint8_t tcipher_total;

#ifndef ELE_PERF
	int len = strlen(line);
	char *test_id = (char *)malloc(len * sizeof(char));

	strncpy(test_id, line, len);
	test_id[len - 1] = '\0';
#endif
	++tcipher_total;
	++(*tests_total);

	se_info("\n-----------------------------------------------\n");
	se_info("%s", line);
	se_info("-----------------------------------------------\n");

#ifdef PSA_COMPLIANT
	if (memcmp(line, "TEST_CIPHER_PSA", 15) != 0) {
		se_info("Skipping Test: Test Case is NOT PSA_COMPLIANT\n");
		goto out;
	}
#else
	if (memcmp(line, "TEST_CIPHER_NON_PSA", 19) != 0) {
		se_info("Skipping Test: Test Case is PSA_COMPLIANT\n");
		goto out;
	}
#endif
	test_status = prepare_and_run_cipher_test(key_store_hdl, fp);

	if (test_status == TEST_STATUS_SUCCESS) {
		++tcipher_passed;
		++(*tests_passed);
#ifndef ELE_PERF
		printf("%s: SUCCESS\n", test_id);
#endif
	} else if (test_status == TEST_STATUS_FAILED) {
		++tcipher_failed;
		++(*tests_failed);
#ifndef ELE_PERF
		printf("%s: FAILED\n", test_id);
#endif
	} else if (test_status == TEST_STATUS_INVALID) {
		++tcipher_invalids;
		++(*tests_invalid);
#ifndef ELE_PERF
		printf("%s: INVALID\n", test_id);
#endif
	} else if (test_status == TEST_STATUS_SKIPPED) {
		--tcipher_total;
		--(*tests_total);
#ifndef ELE_PERF
		printf("%s: SKIPPED\n", test_id);
#endif
	}

#ifndef ELE_PERF
	if (test_id)
		free(test_id);
#endif

out:

	se_info("\n------------------------------------------------------------------\n");
	se_info("TCIPHER TESTS STATUS:: TOTAL: %u, SUCCESS: %u, FAILED: %u, INVALID: %u",
		tcipher_total, tcipher_passed, tcipher_failed, tcipher_invalids);
	se_info("\n------------------------------------------------------------------\n\n");

}

