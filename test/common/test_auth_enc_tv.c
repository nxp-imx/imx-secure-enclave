// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#include <stdio.h>
#include <string.h>

#include "hsm_api.h"
#include "test_utils_tv.h"
#include "plat_utils.h"
#include "common.h"

/**
 * In principle any IV size can be used as long as the IV doesn't ever repeat.
 * For CCM and GCM, IV SIZE of 12 bytes is suggested by FW.
 */
#define IV_SIZE 12

/**
 * In general TAG SIZE may vary but value suggested by FW is 16 bytes.
 */
#define TAG_SIZE 16

static hsm_err_t do_auth_enc_test(hsm_hdl_t key_store_hdl, hsm_hdl_t key_mgmt_hdl,
				  uint32_t key_identifier, uint16_t iv_size,
				  uint8_t *iv_data, uint16_t aad_size, uint8_t *aad_data,
				  hsm_op_auth_enc_algo_t ae_algo,
				  hsm_op_auth_enc_flags_t flags,
				  uint32_t plaintext_size, uint8_t *input_data,
				  uint32_t ciphertext_size, uint32_t exp_output_size)
{
	op_auth_enc_args_t auth_enc_args = {0};
	hsm_err_t hsmret = HSM_GENERAL_ERROR;
	uint8_t *ciphered_data = NULL;
	uint8_t *deciphered_data = NULL;
	uint16_t dec_iv_data = 0;
	uint16_t ciphertext_tag_size = 0;
	hsm_hdl_t cipher_hdl = 0;

	memset(&auth_enc_args, 0, sizeof(auth_enc_args));

	ciphered_data = (uint8_t *)malloc(ciphertext_size * sizeof(uint8_t));

	if (!ciphered_data) {
		se_err("\nError: Couldn't allocate memory for Ciphered Data\n");
		goto out;
	}

	deciphered_data = (uint8_t *)malloc(plaintext_size * sizeof(uint8_t));

	if (!deciphered_data) {
		se_err("\nError: Couldn't allocate memory for Deciphered Data\n");
		goto out;
	}

	memset(ciphered_data, 0, sizeof(ciphered_data));
	memset(deciphered_data, 0, sizeof(deciphered_data));

	//ENCRYPT-DECRYPT common part
	auth_enc_args.key_identifier = key_identifier;
	auth_enc_args.iv = iv_data;
	auth_enc_args.iv_size = iv_size;
	auth_enc_args.aad = aad_data;
	auth_enc_args.aad_size = aad_size;
	auth_enc_args.ae_algo = ae_algo;

	//ENCRYPT
	auth_enc_args.flags = HSM_AUTH_ENC_FLAGS_ENCRYPT | flags;
	auth_enc_args.input = input_data;
	auth_enc_args.output = ciphered_data;
	auth_enc_args.input_size = plaintext_size;
	auth_enc_args.output_size = ciphertext_size;
	hsmret = hsm_do_auth_enc(key_store_hdl, &auth_enc_args);

	if (hsmret != HSM_NO_ERROR)
		goto out;

	//DECRYPT
	auth_enc_args.flags = HSM_AUTH_ENC_FLAGS_DECRYPT;
	auth_enc_args.input = ciphered_data;

	//Different IV SIZE based on flag
	if (flags == HSM_AUTH_ENC_FLAGS_GENERATE_FULL_IV ||
	    flags == HSM_AUTH_ENC_FLAGS_GENERATE_COUNTER_IV) {
		dec_iv_data = plaintext_size + TAG_SIZE;
		auth_enc_args.iv_size = IV_SIZE;
		auth_enc_args.iv = auth_enc_args.input + dec_iv_data;
	}

	auth_enc_args.output = deciphered_data;

	//For decryption, input size is ciphertext size plus tag size
	ciphertext_tag_size = plaintext_size + TAG_SIZE;
	auth_enc_args.input_size = ciphertext_tag_size;

	auth_enc_args.output_size = plaintext_size;

	hsmret = hsm_do_auth_enc(key_store_hdl, &auth_enc_args);

	if (hsmret != HSM_NO_ERROR)
		goto out;

	if (memcmp(input_data, deciphered_data, plaintext_size) != 0)
		printf("\nAuth Enc: Decrypted data does not matches Test data\n");

out:
	if (ciphered_data)
		free(ciphered_data);

	if (deciphered_data)
		free(deciphered_data);

	return hsmret;
}

static int8_t prepare_and_run_auth_enc_test(hsm_hdl_t key_store_hdl, FILE *fp)
{
	hsm_err_t ret = HSM_GENERAL_ERROR;
	hsm_hdl_t key_mgmt_hdl = 0;

	uint8_t req_params_n = 13;
	uint8_t input_ctr = 0;
	uint8_t invalid_read = 0;
	uint8_t call_auth_enc_test = -1;
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
	hsm_op_auth_enc_algo_t ae_algo;
	hsm_op_auth_enc_flags_t flags;
	uint32_t expected_rsp_code = 0;
	uint16_t iv_size = 0;
	uint16_t aad_size = 0;
	uint8_t *aad_data = NULL;
	uint32_t input_size = 0;
	uint32_t output_size = 0;
	uint32_t exp_output_size = 0;
	uint8_t *iv_data = NULL;
	uint8_t *input_data = NULL;

	while ((read = getline(&line, &len, fp)) != -1) {
		if (memcmp(line, "TEST_AUTH_ENC_END", 17) == 0) {
			if (input_ctr == req_params_n) {
				call_auth_enc_test = 1;
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

		} else if (strcmp(param_name, "KEY_TV_ID") == 0) {
			key_tv_id = (uint32_t)parse_param_value(param_value_token,
						param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "IV_SIZE") == 0) {
			iv_size = (uint16_t)parse_param_value(param_value_token,
					param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "IV_DATA") == 0) {
			iv_data = (uint8_t *)malloc(iv_size * sizeof(uint8_t));

			if (!iv_data) {
				invalid_read = 1;
				se_info("\nError: Couldn't allocate");
				se_info("memory for %s\n", param_name);
				break;
			}

			parse_param_value_buffer(fp, &iv_data, iv_size, param_name,
						 &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "AAD_SIZE") == 0) {
			aad_size = (uint16_t)parse_param_value(param_value_token,
						param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "AAD_DATA") == 0) {
			aad_data = (uint8_t *)malloc(aad_size * sizeof(uint8_t));

			if (!aad_data) {
				invalid_read = 1;
				se_info("\nError: Couldn't allocate");
				se_info("memory for %s\n", param_name);
				break;
			}

			parse_param_value_buffer(fp, &aad_data, aad_size, param_name,
						 &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "AE_ALGO") == 0) {
			ae_algo = (hsm_op_auth_enc_algo_t)
				parse_param_value(param_value_token,
						  param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "FLAGS") == 0) {
			flags = (hsm_op_auth_enc_flags_t)
				 parse_param_value(param_value_token,
						   param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "INPUT_SIZE") == 0) {
			input_size = (uint32_t)parse_param_value(param_value_token,
						param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "INPUT_DATA") == 0) {
			input_data = (uint8_t *)malloc(input_size * sizeof(uint8_t));

			if (!input_data) {
				invalid_read = 1;
				se_info("\nError: Couldn't allocate");
				se_info("memory for %s\n", param_name);
				break;
			}

			parse_param_value_buffer(fp, &input_data, input_size, param_name,
						 &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "OUTPUT_SIZE") == 0) {
			output_size = (uint32_t)parse_param_value(param_value_token,
						param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "EXP_OUTPUT_SIZE") == 0) {
			exp_output_size = (uint32_t)parse_param_value(param_value_token,
						param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "EXPECTED_HSM_RESP") == 0) {
			expected_rsp_code = (uint32_t)parse_param_value(param_value_token,
						param_name, &input_ctr, &invalid_read);
		}

		/* Invalid value for any param. */
		if (invalid_read == 1)
			break;
	}

	if (call_auth_enc_test == 1) {
		se_info("Key MGMT TV ID    : %u\n", key_mgmt_tv_id);
		se_info("Key TV ID         : %u\n", key_tv_id);
		se_info("IV Size           : %u\n", iv_size);
		se_info("\nIV Data         :\n");
		hexdump_bb(iv_data, iv_size);
		se_info("AAD Size          : %u\n", aad_size);
		se_info("\nAAD Data        :\n");
		hexdump_bb(aad_data, aad_size);
		se_info("AE Algo           : 0x%x\n", ae_algo);
		se_info("Flags             : 0x%x\n", flags);
		se_info("Input Size        : %u\n", input_size);
		se_info("Input Data        :\n");
		hexdump_bb(input_data, input_size);
		se_info("Output Size       : %u\n", output_size);
		se_info("Expected Output Size: %u\n", exp_output_size);
		se_info("Expected HSM Resp : 0x%x\n", expected_rsp_code);

		se_info("----------------------------------------------------\n");

		key_mgmt_hdl = get_key_mgmt_hdl(key_mgmt_tv_id);
		key_identifier = get_test_key_identifier(key_tv_id);
		ret = do_auth_enc_test(key_store_hdl, key_mgmt_hdl, key_identifier,
				       iv_size, iv_data, aad_size, aad_data, ae_algo,
				       flags, input_size, input_data, output_size,
				       exp_output_size);

		if (ret == expected_rsp_code)
			test_status = TEST_STATUS_SUCCESS;
		else
			test_status = TEST_STATUS_FAILED;
	}

	if (invalid_read == 1 || read == -1) {
		test_status = TEST_STATUS_FAILED;

		/* EOF encountered before reading all param values. */
		if (read == -1)
			se_info("\nEOF reached. TEST_AUTH_ENC_END not detected.\n");
	}

	if (iv_data)
		free(iv_data);

	if (aad_data)
		free(aad_data);

	if (input_data)
		free(input_data);

	if (line)
		free(line);

	return test_status;
}

void auth_enc_test_tv(hsm_hdl_t key_store_hdl, FILE *fp, char *line,
		      uint16_t *tests_passed, uint16_t *tests_failed,
		      uint16_t *tests_invalid, uint16_t *tests_total)
{
	int8_t test_status = TEST_STATUS_FAILED;
	static uint16_t tauth_enc_passed;
	static uint16_t tauth_enc_failed;
	static uint16_t tauth_enc_invalids;
	static uint16_t tauth_enc_total;

	int len = strlen(line);
	char *test_id = (char *)malloc(len * sizeof(char));

	snprintf(test_id, len, "%s", line);
	++tauth_enc_total;
	++(*tests_total);

	se_info("\n-----------------------------------------------\n");
	se_info("%s", line);
	se_info("-----------------------------------------------\n");

#ifdef PSA_COMPLIANT
	if (memcmp(line, "TEST_AUTH_ENC_PSA", 17) != 0) {
		se_info("Skipping Test: Test Case is NOT PSA_COMPLIANT\n");
		goto out;
	}
#else
	if (memcmp(line, "TEST_AUTH_ENC_NON_PSA", 21) != 0) {
		se_info("Skipping Test: Test Case is PSA_COMPLIANT\n");
		goto out;
	}
#endif
	test_status = prepare_and_run_auth_enc_test(key_store_hdl, fp);

	if (test_status == TEST_STATUS_SUCCESS) {
		printf("%s: SUCCESS\n", test_id);
		++tauth_enc_passed;
		++(*tests_passed);
	} else if (test_status == TEST_STATUS_FAILED) {
		printf("%s: FAILED\n", test_id);
		++tauth_enc_failed;
		++(*tests_failed);
	} else if (test_status == TEST_STATUS_INVALID) {
		printf("%s: INVALID\n", test_id);
		++tauth_enc_invalids;
		++(*tests_invalid);
	} else if (test_status == TEST_STATUS_SKIPPED) {
		printf("%s: SKIPPED\n", test_id);
		--tauth_enc_total;
		--(*tests_total);
	}

out:
	if (test_id)
		free(test_id);

	se_info("\n------------------------------------------------------------------\n");
	se_info("TAUTH_ENC TESTS STATUS:: TOTAL: %u, SUCCESS: %u, FAILED: %u, INVALID: %u",
		tauth_enc_total, tauth_enc_passed, tauth_enc_failed, tauth_enc_invalids);
	se_info("\n------------------------------------------------------------------\n\n");
}
