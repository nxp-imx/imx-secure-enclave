/*
 * Copyright 2022-2023 NXP
 *
 * NXP Confidential.
 * This software is owned or controlled by NXP and may only be used strictly
 * in accordance with the applicable license terms.  By expressly accepting
 * such terms or by downloading, installing, activating and/or otherwise using
 * the software, you are agreeing that you have read, and that you agree to
 * comply with and are bound by, such license terms.  If you do not agree to be
 * bound by the applicable license terms, then you may not retain, install,
 * activate or otherwise use the software.
 */

#include <stdio.h>

#include "hsm_api.h"
#include "test_utils_tv.h"

static hsm_err_t cipher_test(hsm_hdl_t key_store_hdl, hsm_hdl_t key_mgmt_hdl,
				uint32_t key_identifier, hsm_op_cipher_one_go_algo_t cipher_algo,
				uint16_t iv_size, uint8_t *iv_data, uint32_t plaintext_size,
				uint8_t *input_data, uint32_t ciphertext_size)
{
	op_cipher_one_go_args_t cipher_args = {0};
	hsm_err_t hsmret = HSM_GENERAL_ERROR;
	uint8_t *ciphered_data = NULL;
	uint8_t *deciphered_data = NULL;
	hsm_hdl_t cipher_hdl = 0;

	memset(&cipher_args, 0, sizeof(cipher_args));

	ciphered_data = (uint8_t *) malloc(ciphertext_size*sizeof(uint8_t));

	if (ciphered_data == NULL) {
		printf("\nError: Couldn't allocate memory for Ciphered Data\n");
		goto out;
	}

	deciphered_data = (uint8_t *) malloc(plaintext_size*sizeof(uint8_t));

	if (deciphered_data == NULL) {
		printf("\nError: Couldn't allocate memory for Deciphered Data\n");
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

	hsmret = hsm_do_cipher(key_store_hdl, &cipher_args);
	printf("\nENCRYPT: hsm_do_cipher ret: 0x%x\n", hsmret);

	if (hsmret != HSM_NO_ERROR)
		goto out;

#ifdef DEBUG
	printf("\nEncrypted data:\n");
	print_buffer(ciphered_data, ciphertext_size);
#endif

	//DECRYPT
	cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_DECRYPT;
	cipher_args.input = ciphered_data;
	cipher_args.output = deciphered_data;
	cipher_args.input_size = ciphertext_size;
	cipher_args.output_size = plaintext_size;

	hsmret = hsm_do_cipher(key_store_hdl, &cipher_args);
	printf("\nDECRYPT: hsm_do_cipher ret: 0x%x\n", hsmret);

	if (hsmret != HSM_NO_ERROR)
		goto out;

#ifdef DEBUG
	printf("\nDecrypted data:\n");
	print_buffer(deciphered_data, plaintext_size);
	printf("\n----------------------------------------------------\n");
#endif

	if (memcmp(input_data, deciphered_data, plaintext_size) == 0)
		printf("\nDecrypted data matches Encrypted data [PASS]\n");
	else
		printf("\nDecrypted data doesn't match Encrypted data [FAIL]\n");

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
	hsm_op_cipher_one_go_algo_t cipher_algo;
	uint32_t expected_rsp_code = 0;
	uint16_t iv_size = 0;
	uint32_t input_size = 0;
	uint32_t output_size = 0;
	uint8_t *iv_data = NULL;
	uint8_t *input_data = NULL;

	while ((read = getline(&line, &len, fp)) != -1) {

		if (memcmp(line, "TEST_CIPHER_END", 15) == 0) {

			if (input_ctr == req_params_n) {
				call_cipher_test = 1;
			} else {
				/* Invalid Test case due to less no. of params than required*/
				invalid_read = 1;
				printf("Failed to read all required params (%u/%u)\n",
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
				printf("\nError: Couldn't allocate memory for %s\n", param_name);
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
				printf("\nError: Couldn't allocate memory for %s\n", param_name);
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

		printf("Key MGMT TV ID    : %u\n", key_mgmt_tv_id);
		printf("Key TV ID         : %u\n", key_tv_id);
		printf("Cipher Algo       : 0x%x\n", cipher_algo);
		printf("IV Size           : %u\n", iv_size);
		printf("Input Size        : %u\n", input_size);
		printf("Output Size       : %u\n", output_size);
		printf("Expected HSM Resp : 0x%x\n", expected_rsp_code);
		printf("\nIV Data           :\n");
		print_buffer(iv_data, iv_size);
		printf("Input Data        :\n");
		print_buffer(input_data, input_size);

		printf("----------------------------------------------------\n");

		key_mgmt_hdl = get_key_mgmt_hdl(key_mgmt_tv_id);
		key_identifier = get_test_key_identifier(key_tv_id);

		ret = cipher_test(key_store_hdl, key_mgmt_hdl, key_identifier,
					cipher_algo, iv_size, iv_data, input_size, input_data,
					output_size);

		if (ret == expected_rsp_code) {
			test_status = 1;
			printf("\nTEST RESULT: SUCCESS\n");
		} else {
			test_status = 0;
			printf("\nTEST RESULT: FAILED\n");
		}

		printf("\ncipher_test ret: 0x%x\n", ret);
	}

	if (invalid_read == 1 || read == -1) {
		test_status = -1;

		/* EOF encountered before reading all param values. */
		if (read == -1)
			printf("\nEOF reached. TEST_CIPHER_END not detected.\n");

		printf("\nSkipping this Test Case\n");
		printf("\nTEST_RESULT: INVALID\n");
	}

	if (iv_data)
		free(iv_data);

	if (input_data)
		free(input_data);

	if (line)
		free(line);

	return test_status;
}

void cipher_test_tv(hsm_hdl_t key_store_hdl, FILE *fp, char *line)
{
	int8_t test_status = 0;
	static uint8_t tcipher_passed;
	static uint8_t tcipher_failed;
	static uint8_t tcipher_invalids;
	static uint8_t tcipher_total;

	++tcipher_total;

	printf("\n-----------------------------------------------\n");
	printf("%s", line);
	printf("-----------------------------------------------\n");

#ifdef PSA_COMPLIANT
	if (memcmp(line, "TEST_CIPHER_PSA", 15) != 0) {
		printf("Skipping Test: Test Case is NOT PSA_COMPLIANT\n");
		goto out;
	}
#else
	if (memcmp(line, "TEST_CIPHER_NON_PSA", 19) != 0) {
		printf("Skipping Test: Test Case is PSA_COMPLIANT\n");
		goto out;
	}
#endif
	test_status = prepare_and_run_cipher_test(key_store_hdl, fp);

	if (test_status == 1)
		++tcipher_passed;
	else if (test_status == 0)
		++tcipher_failed;
	else if (test_status == -1)
		++tcipher_invalids;

out:

	printf("\n------------------------------------------------------------------\n");
	printf("TCIPHER TESTS STATUS:: TOTAL: %u, SUCCESS: %u, FAILED: %u, INVALID: %u",
		tcipher_total, tcipher_passed, tcipher_failed, tcipher_invalids);
	printf("\n------------------------------------------------------------------\n\n");

}

