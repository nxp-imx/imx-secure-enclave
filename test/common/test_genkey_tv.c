/*
 * Copyright 2022 NXP
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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "hsm_api.h"
#include "test_utils_tv.h"

static hsm_err_t generate_key(hsm_hdl_t key_mgmt_hdl,
#ifdef CONFIG_PLAT_SECO
				hsm_key_info_t key_info,
#else
				hsm_key_lifetime_t key_lifetime,
				hsm_key_usage_t key_usage,
				hsm_permitted_algo_t permitted_algo,
#endif
				hsm_key_type_t key_type,
				hsm_key_group_t key_group,
				uint8_t *out_key,
				uint16_t out_size,
				uint32_t *key_identifier)
{
	op_generate_key_args_t key_gen_args = {0};

	memset(&key_gen_args, 0, sizeof(key_gen_args));

	key_gen_args.key_identifier = key_identifier;
	key_gen_args.out_size = out_size;
	key_gen_args.key_group = key_group;
#ifdef CONFIG_PLAT_SECO
	key_gen_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE;
	key_gen_args.key_info = key_info;
#else
	key_gen_args.key_lifetime = key_lifetime;
	key_gen_args.key_usage = key_usage;
	key_gen_args.permitted_algo = permitted_algo;
#endif
	key_gen_args.key_type = key_type;
	key_gen_args.out_key = out_key;

	return hsm_generate_key(key_mgmt_hdl, &key_gen_args);
}

static int8_t prepare_and_run_genkey_test(FILE *fp)
{
	hsm_err_t ret = HSM_GENERAL_ERROR;
	hsm_hdl_t key_mgmt_hdl = 0;

#ifdef PSA_COMPLIANT
	uint8_t req_params_n = 10;
#else
	uint8_t req_params_n = 8;
#endif
	uint8_t input_ctr = 0;
	uint8_t invalid_read = 0;
	uint8_t call_gen_key = -1;
	int8_t test_status = 0; /* 0 -> FAILED, 1 -> PASSED, -1 -> INVALID*/
	size_t len = 0;
	ssize_t read = 0;

	char *param_name = NULL;
	char *param_value_token = NULL;
	char *temp = NULL;
	char *line = NULL;

	uint32_t key_mgmt_tv_id = 0;
	uint32_t key_tv_id = 0;      // Key TV ID to use the key after generation
	uint32_t key_identifier = 0;
	uint8_t *out_key = NULL;
	uint16_t out_size = 0;
	hsm_key_type_t key_type;
	hsm_key_group_t key_group;
 #ifdef PSA_COMPLIANT
	hsm_key_lifetime_t key_lifetime;
	hsm_key_usage_t key_usage;
	hsm_permitted_algo_t permitted_algo;
#else
	hsm_key_info_t key_info;
#endif
	uint32_t expected_rsp_code = 0;

	while ((read = getline(&line, &len, fp)) != -1) {

		if (memcmp(line, "TEST_KGEN_END", 13) == 0) {

			if (input_ctr == req_params_n) {
				call_gen_key = 1;
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

		} else if (strcmp(param_name, "KEY_ID") == 0) {

			key_identifier = (uint32_t)parse_param_value(param_value_token,
							param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "OUT_SIZE") == 0) {

			out_size = (uint16_t)parse_param_value(param_value_token,
							param_name, &input_ctr, &invalid_read);

			/* For asymmetric key, allocate output key buffer of out_size bytes */
			if ((out_size > 0) && (out_size <= 4096)) {

				out_key = (uint8_t *) malloc(out_size * sizeof(uint8_t));

				if (out_key == NULL) {
					invalid_read = 1;
					printf("\nError: Couldn't allocate memory for Output Public Key\n");
					break;
				}
			}

		} else if (strcmp(param_name, "KEY_TYPE") == 0) {

			key_type = (hsm_key_type_t)parse_param_value(param_value_token,
							param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "KEY_GROUP") == 0) {

			key_group = (hsm_key_group_t)parse_param_value(param_value_token,
							param_name, &input_ctr, &invalid_read);

#ifdef PSA_COMPLIANT

		} else if (strcmp(param_name, "KEY_LIFETIME") == 0) {

			key_lifetime =	(hsm_key_lifetime_t)parse_param_value(param_value_token,
							param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "KEY_USAGE") == 0) {

			key_usage = (hsm_key_usage_t)parse_param_value(param_value_token,
							param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "PERMITTED_ALGO") == 0) {

			permitted_algo = (hsm_permitted_algo_t)parse_param_value(param_value_token,
							param_name, &input_ctr, &invalid_read);

#else
		} else if (strcmp(param_name, "KEY_INFO") == 0) {

			key_info = (hsm_key_info_t)parse_param_value(param_value_token,
							param_name, &input_ctr, &invalid_read);

#endif
		} else if (strcmp(param_name, "EXPECTED_HSM_RESP") == 0) {

			expected_rsp_code = (uint32_t)parse_param_value(param_value_token,
							param_name, &input_ctr, &invalid_read);

		}

		/* Invalid value for any param. */
		if (invalid_read == 1)
			break;
	}

	if (call_gen_key == 1) {
		printf("Key MGMT TV ID : %u\n", key_mgmt_tv_id);
		printf("Key TV ID      : %u\n", key_tv_id);
		printf("Key ID         : 0x%x\n", key_identifier);
		printf("Out Size       : %u\n", out_size);
		printf("Key Type       : 0x%x\n", key_type);
		printf("Key Group      : %u\n", key_group);
#ifdef PSA_COMPLIANT
		printf("Key Lifetime   : 0x%x\n", key_lifetime);
		printf("Key Usage      : 0x%x\n", key_usage);
		printf("Permitted Algo : 0x%x\n", permitted_algo);
#else
		printf("Key Info       : 0x%x\n", key_info);
#endif
		printf("Expected Resp  : 0x%x\n\n", expected_rsp_code);

		/* Getting Key Management handle for given Key Mgmt TV ID */
		key_mgmt_hdl = get_key_mgmt_hdl(key_mgmt_tv_id);

		ret = generate_key(key_mgmt_hdl,
#ifndef PSA_COMPLIANT
					key_info,
#else
					key_lifetime, key_usage, permitted_algo,
#endif
					key_type, key_group, out_key, out_size, &key_identifier);

		if (ret == expected_rsp_code) {
			test_status = 1;
			printf("\nTEST RESULT: SUCCESS\n");
		} else {
			test_status = 0;
			printf("\nTEST RESULT: FAILED\n");
		}

		printf("\nhsm_generate_key ret: 0x%x\n", ret);

		if (ret == HSM_NO_ERROR)
			save_test_key(key_tv_id, key_identifier, key_mgmt_tv_id,
						key_group, key_type);
	}

	if (invalid_read == 1 || read == -1) {
		test_status = -1;

		/* EOF encountered before reading all param values. */
		if (read == -1)
			printf("\nEOF reached. TEST_KGEN_END not detected.\n");

		printf("\nSkipping this Test Case\n");
		printf("\nTEST_RESULT: INVALID\n");
	}

	free(out_key);
	free(line);
	return test_status;
}

void generate_key_test_tv(hsm_hdl_t key_store_hdl, FILE *fp, char *line)
{
	int8_t test_status = 0;
	static uint8_t tkgen_passed;
	static uint8_t tkgen_failed;
	static uint8_t tkgen_invalids;
	static uint8_t tkgen_total;

	++tkgen_total;

	printf("\n-----------------------------------------------\n");
	printf("%s", line);
	printf("-----------------------------------------------\n");

#ifdef PSA_COMPLIANT
	if (memcmp(line, "TEST_KGEN_PSA", 13) != 0) {
		printf("Skipping Test: Test Case is NOT PSA_COMPLIANT\n");
		goto out;
	}
#else
	if (memcmp(line, "TEST_KGEN_NON_PSA", 17) != 0) {
		printf("Skipping Test: Test Case is PSA_COMPLIANT\n");
		goto out;
	}
#endif
	test_status = prepare_and_run_genkey_test(fp);

	if (test_status == 1)
		++tkgen_passed;
	else if (test_status == 0)
		++tkgen_failed;
	else if (test_status == -1)
		++tkgen_invalids;

out:

	printf("\n------------------------------------------------------------------\n");
	printf("TKGEN TESTS STATUS:: TOTAL: %u, SUCCESS: %u, FAILED: %u, INVALID: %u",
			tkgen_total, tkgen_passed, tkgen_failed, tkgen_invalids);
	printf("\n------------------------------------------------------------------\n\n");

}
