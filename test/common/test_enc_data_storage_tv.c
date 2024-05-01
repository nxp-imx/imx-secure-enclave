// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#include <stdio.h>
#include <string.h>

#include "hsm_api.h"
#include "test_utils_tv.h"
#include "plat_utils.h"
#include "test_common.h"

static hsm_err_t do_enc_data_storage_test(hsm_hdl_t key_store_hdl,
					  hsm_hdl_t key_mgmt_hdl,
					  uint32_t data_id,
					  uint32_t data_size,
					  uint8_t *data,
					  hsm_op_cipher_one_go_algo_t cipher_algo,
					  uint32_t enc_key_identifier,
					  uint16_t iv_size,
					  uint8_t *iv_data,
					  hsm_permitted_algo_t sign_algo,
					  uint32_t sign_key_identifier,
					  hsm_svc_data_storage_flags_t svc_flags,
					  hsm_op_enc_data_storage_flags_t flags,
#ifdef PSA_COMPLIANT
					  hsm_key_lifecycle_t lifecycle,
#endif
					  uint32_t expected_rsp_code,
					  int8_t *test_status)
{
	op_enc_data_storage_args_t enc_data_storage_args = {0};
	op_data_storage_args_t data_storage_args = {0};
	uint8_t *retrieved_enc_data = NULL;
	hsm_err_t err;
	*test_status = TEST_STATUS_FAILED;

	memset(&enc_data_storage_args, 0, sizeof(enc_data_storage_args));
	memset(&data_storage_args, 0, sizeof(data_storage_args));

	// Store Data after encryption and signing
	enc_data_storage_args.svc_flags = svc_flags;
	enc_data_storage_args.data = data;
	enc_data_storage_args.data_size = data_size;
	enc_data_storage_args.data_id = data_id;
	enc_data_storage_args.enc_algo = cipher_algo;
	enc_data_storage_args.enc_key_id = enc_key_identifier;
	enc_data_storage_args.iv = iv_data;
	enc_data_storage_args.iv_size = iv_size;
	enc_data_storage_args.sign_algo = sign_algo;
	enc_data_storage_args.sign_key_id = sign_key_identifier;
	enc_data_storage_args.flags = flags;
#ifdef PSA_COMPLIANT
	enc_data_storage_args.lifecycle = lifecycle;
#endif
	err = hsm_enc_data_ops(key_store_hdl, &enc_data_storage_args);
	se_info("hsm_enc_data_ops [STORE] err:0x%x\n", err);

	if (err != expected_rsp_code)
		goto out;

	//Retrieve Encrypted and Signed Data stored in NVM
	retrieved_enc_data = (uint8_t *)malloc
			     (enc_data_storage_args.out_data_size * sizeof(uint8_t));

	if (!retrieved_enc_data) {
		se_err("\nError: Couldn't allocate memory for Data\n");
		goto out;
	}

	memset(retrieved_enc_data, 0, enc_data_storage_args.out_data_size
	       * sizeof(uint8_t));

#ifdef PSA_COMPLIANT
	data_storage_args.svc_flags = svc_flags;
#endif
	data_storage_args.data = retrieved_enc_data;
	data_storage_args.data_size = enc_data_storage_args.out_data_size;
	data_storage_args.data_id = data_id;
	data_storage_args.flags = HSM_OP_DATA_STORAGE_FLAGS_RETRIEVE;

	err = hsm_data_ops(key_store_hdl, &data_storage_args);
	se_info("hsm_data_ops [RETRIEVE] err:0x%x\n", err);

	if (err != expected_rsp_code)
		goto out;

	*test_status = TEST_STATUS_SUCCESS;
out:
	if (retrieved_enc_data)
		free(retrieved_enc_data);
}

static int8_t prepare_and_run_enc_data_storage_test(hsm_hdl_t key_store_hdl, FILE *fp)
{
	hsm_hdl_t key_mgmt_hdl = 0;
	hsm_hdl_t sess_hdl = get_hsm_session_hdl();

	uint8_t req_params_n = 14;
	uint8_t input_ctr = 0;
	uint8_t invalid_read = 0;
	uint8_t call_enc_data_storage_test = -1;
	int8_t test_status = TEST_STATUS_FAILED;
	size_t len = 0;
	ssize_t read = 0;

	char *param_name = NULL;
	char *param_value_token = NULL;
	char *temp = NULL;
	char *line = NULL;

	uint32_t key_mgmt_tv_id = 0;
	uint32_t enc_key_identifier = 0;
	uint32_t sign_key_identifier = 0;
	uint32_t enc_key_id = 0;
	uint32_t sign_key_id = 0;
	hsm_op_enc_data_storage_flags_t flags;
	hsm_svc_data_storage_flags_t svc_flags;
	uint32_t data_id = 0;
	uint32_t data_size = 0;
	uint8_t *data = NULL;
	hsm_op_cipher_one_go_algo_t cipher_algo;
	hsm_permitted_algo_t sign_algo;
	uint8_t *iv_data = NULL;
	uint16_t iv_size = 0;
#ifdef PSA_COMPLIANT
	hsm_key_lifecycle_t lifecycle;
#endif
	uint32_t expected_rsp_code = 0;

	while ((read = getline(&line, &len, fp)) != -1) {
		if (memcmp(line, "TEST_ENC_DATA_STORAGE_END", 25) == 0) {
			if (input_ctr == req_params_n) {
				call_enc_data_storage_test = 1;
			} else {
				/* Invalid Test case due to less no. of
				 * params than required
				 */
				invalid_read = 1;
				se_info("Failed to read all required params (%u/%u)\n",
					input_ctr, req_params_n);
			}

			break;
		}

		/* Tokenizing param_name and param_value_token from line.*/
		param_name = strtok_r(line, " ", &temp);

		if (!param_name) {
			continue;
		} else {
			param_value_token = strtok_r(NULL, " ", &temp);

			if (!param_value_token)
				continue;
		}

		if (strcmp(param_name, "KEY_MGMT_TV_ID") == 0) {
			key_mgmt_tv_id = (uint32_t)parse_param_value(param_value_token,
						param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "DATA_ID") == 0) {
			data_id = (uint32_t)parse_param_value(param_value_token,
						param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "DATA_SIZE") == 0) {
			data_size = (uint32_t)parse_param_value(param_value_token,
					param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "DATA") == 0) {
			data = (uint8_t *)malloc(data_size * sizeof(uint8_t));

			if (!data) {
				invalid_read = 1;
				printf("\nError: Couldn't allocate");
				printf("memory for %s\n", param_name);
				break;
			}

			parse_param_value_buffer(fp, &data, data_size, param_name,
						 &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "ENC_ALGO") == 0) {
			cipher_algo = (hsm_op_cipher_one_go_algo_t)parse_param_value
				      (param_value_token, param_name, &input_ctr,
				       &invalid_read);

		} else if (strcmp(param_name, "ENC_KEY_ID") == 0) {
			enc_key_id = (uint32_t)parse_param_value(param_value_token,
				      param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "IV_SIZE") == 0) {
			iv_size = (uint16_t)parse_param_value(param_value_token,
						param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "IV_DATA") == 0) {
			iv_data = (uint8_t *)malloc(iv_size * sizeof(uint8_t));

			if (!iv_data) {
				invalid_read = 1;
				printf("\nError: Couldn't allocate");
				printf("memory for %s\n", param_name);
				break;
			}

			parse_param_value_buffer(fp, &iv_data, iv_size, param_name,
						 &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "SIGN_ALGO") == 0) {
			sign_algo = (hsm_permitted_algo_t)
				 parse_param_value(param_value_token,
						   param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "SIGN_KEY_ID") == 0) {
			sign_key_id = (uint32_t)parse_param_value(param_value_token,
						param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "SVC_FLAGS") == 0) {
			svc_flags = (hsm_svc_data_storage_flags_t)
				parse_param_value(param_value_token,
						  param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "FLAGS") == 0) {
			flags = (hsm_op_enc_data_storage_flags_t)
				parse_param_value(param_value_token,
						  param_name, &input_ctr, &invalid_read);
#ifdef PSA_COMPLIANT
		} else if (strcmp(param_name, "LIFECYCLE") == 0) {
			lifecycle = (hsm_key_lifecycle_t)parse_param_value
				    (param_value_token, param_name, &input_ctr,
				     &invalid_read);
#endif
		} else if (strcmp(param_name, "EXPECTED_HSM_RESP") == 0) {
			expected_rsp_code = (uint32_t)parse_param_value(param_value_token,
						param_name, &input_ctr, &invalid_read);
		}

		/* Invalid value for any param. */
		if (invalid_read == 1)
			break;
	}

	if (call_enc_data_storage_test == 1) {
		if (data_size > 2048) {
			test_status = TEST_STATUS_SKIPPED;
			goto out;
		}

#ifdef PSA_COMPLIANT
		/* Skipping Test Cases Based on Lifecycle*/
		if (se_get_chip_lifecycle() != lifecycle) {
			test_status = TEST_STATUS_SKIPPED;
			goto out;
		}
#endif
		key_mgmt_hdl = get_key_mgmt_hdl(key_mgmt_tv_id);
		enc_key_identifier = get_test_key_identifier(enc_key_id);
		sign_key_identifier = get_test_key_identifier(sign_key_id);
		do_enc_data_storage_test(key_store_hdl, key_mgmt_hdl, data_id,
					 data_size, data, cipher_algo,
					 enc_key_identifier, iv_size, iv_data,
					 sign_algo, sign_key_identifier,
					 svc_flags, flags,
#ifdef PSA_COMPLIANT
					 lifecycle,
#endif
					 expected_rsp_code, &test_status);
	}

	if (invalid_read == 1 || read == -1) {
		test_status = TEST_STATUS_INVALID;

		/* EOF encountered before reading all param values. */
		if (read == -1)
			se_info("\nEOF reached. TEST_ENC_DATA_STORGAE_END not detected.\n");

		se_info("\nSkipping this Test Case\n");
	}

out:
	if (data)
		free(data);

	if (iv_data)
		free(iv_data);

	if (line)
		free(line);

	return test_status;
}

void enc_data_storage_test_tv(hsm_hdl_t key_store_hdl, FILE *fp, char *line,
			      uint16_t *tests_passed, uint16_t *tests_failed,
			      uint16_t *tests_invalid, uint16_t *tests_total)
{
	int8_t test_status = TEST_STATUS_FAILED;
	static uint16_t tenc_data_storage_passed;
	static uint16_t tenc_data_storage_failed;
	static uint16_t tenc_data_storage_invalids;
	static uint16_t tenc_data_storage_total;

	int len = strlen(line);
	char *test_id = (char *)malloc(len * sizeof(char));

	if (!test_id) {
		se_err("\nError: Couldn't allocate memory for Test ID\n");
		goto out;
	}

	snprintf(test_id, len, "%s", line);

	++tenc_data_storage_total;
	++(*tests_total);

	se_info("\n-----------------------------------------------\n");
	se_info("%s", line);
	se_info("-----------------------------------------------\n");

#ifdef PSA_COMPLIANT
	if (memcmp(line, "TEST_ENC_DATA_STORAGE_PSA", 25) != 0) {
		printf("Skipping Test: Test Case is NOT PSA_COMPLIANT\n");
		goto out;
	}
#else
	if (memcmp(line, "TEST_ENC_DATA_STORAGE_NON_PSA", 29) != 0) {
		printf("Skipping Test: Test Case is PSA_COMPLIANT\n");
		goto out;
	}
#endif

	test_status = prepare_and_run_enc_data_storage_test(key_store_hdl, fp);

	if (test_status == TEST_STATUS_SUCCESS) {
		printf("%s: SUCCESS\n", test_id);
		++tenc_data_storage_passed;
		++(*tests_passed);
	} else if (test_status == TEST_STATUS_FAILED) {
		printf("%s: FAILED\n", test_id);
		++tenc_data_storage_failed;
		++(*tests_failed);
	} else if (test_status == TEST_STATUS_INVALID) {
		printf("%s: INVALID\n", test_id);
		++tenc_data_storage_invalids;
		++(*tests_invalid);
	} else if (test_status == TEST_STATUS_SKIPPED) {
		printf("%s: SKIPPED\n", test_id);
		--tenc_data_storage_total;
		--(*tests_total);
	}

out:
	if (test_id)
		free(test_id);

	se_info("\n------------------------------------------------------------------\n");
	se_info("TENC_DATA_STOAGE TESTS STATUS:: TOTAL: %u, SUCCESS: %u, FAILED: %u, INVALID: %u",
		tenc_data_storage_total, tenc_data_storage_passed,
		tenc_data_storage_failed, tenc_data_storage_invalids);
	se_info("\n------------------------------------------------------------------\n\n");
}
