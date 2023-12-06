// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "hsm_api.h"
#include "test_utils_tv.h"
#include "plat_utils.h"

static hsm_err_t generate_key(hsm_hdl_t key_mgmt_hdl,
				hsm_key_type_t key_type,
				hsm_key_group_t key_group,
				hsm_op_key_gen_flags_t flags,
				uint8_t *out_key,
				uint16_t out_size,
#ifndef PSA_COMPLIANT
				hsm_key_info_t key_info,
#else
				hsm_key_lifetime_t key_lifetime,
				hsm_key_usage_t key_usage,
				hsm_permitted_algo_t permitted_algo,
				hsm_bit_key_sz_t bit_key_sz,
				hsm_key_lifecycle_t key_lifecycle,
#endif
				uint32_t *key_identifier)
{
	op_generate_key_args_t key_gen_args = {0};

	memset(&key_gen_args, 0, sizeof(key_gen_args));

	key_gen_args.key_identifier = key_identifier;
	key_gen_args.out_size = out_size;
	key_gen_args.flags = flags;
	key_gen_args.key_group = key_group;
#ifndef PSA_COMPLIANT
	key_gen_args.key_info = key_info;
#else
	key_gen_args.key_lifetime = key_lifetime;
	key_gen_args.key_usage = key_usage;
	key_gen_args.permitted_algo = permitted_algo;
	key_gen_args.bit_key_sz = bit_key_sz;
	key_gen_args.key_lifecycle = key_lifecycle;
#endif
	key_gen_args.key_type = key_type;
	key_gen_args.out_key = out_key;

	return hsm_generate_key(key_mgmt_hdl, &key_gen_args);
}

static hsm_err_t get_key_attributes(hsm_hdl_t key_mgmt_hdl, uint32_t key_identifier)
{
	hsm_err_t ret = HSM_GENERAL_ERROR;
#ifdef PSA_COMPLIANT
	op_get_key_attr_args_t keyattr_args = {0};

	keyattr_args.key_identifier = key_identifier;
	ret = hsm_get_key_attr(key_mgmt_hdl, &keyattr_args);
	se_info("\nhsm_get_key_attr ret: 0x%x\n", ret);

	se_info("\n---------------------------------------------------\n");
	se_info("\nKey Attributes - Key ID (%u / 0x%x)\n",
		key_identifier, key_identifier);
	se_info("\n---------------------------------------------------\n");

	se_info("Key Type      : 0x%04x\n", keyattr_args.key_type);
	se_info("Key Size      : %d\n", keyattr_args.bit_key_sz);
	se_info("Key Lifetime  : 0x%08x\n", keyattr_args.key_lifetime);
	se_info("Key Usage     : 0x%08x\n", keyattr_args.key_usage);
	se_info("Key Algorithm : 0x%08x\n", keyattr_args.permitted_algo);
	se_info("Key Lifecycle : 0x%08x\n", keyattr_args.lifecycle);
#endif
	return ret;
}

static int8_t prepare_and_run_genkey_test(FILE *fp)
{
	hsm_err_t ret = HSM_GENERAL_ERROR;
	hsm_hdl_t key_mgmt_hdl = 0;

#ifdef PSA_COMPLIANT
	uint8_t req_params_n = 13;
#else
	uint8_t req_params_n = 9;
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
	hsm_op_key_gen_flags_t flags;
	hsm_key_group_t key_group;
#ifdef PSA_COMPLIANT
	hsm_bit_key_sz_t bit_key_sz;
	hsm_key_lifecycle_t key_lifecycle;
	hsm_key_lifetime_t key_lifetime;
	hsm_key_usage_t key_usage;
	hsm_permitted_algo_t permitted_algo;
#else
	hsm_key_info_t key_info;
#endif
	uint32_t expected_rsp_code = 0;

	op_get_key_attr_args_t keyattr_args = {0};

	while ((read = getline(&line, &len, fp)) != -1) {

		if (memcmp(line, "TEST_KGEN_END", 13) == 0) {

			if (input_ctr == req_params_n) {
				call_gen_key = 1;
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
					se_info("\nError: Couldn't allocate memory for Output Public Key\n");
					break;
				}
			}

		} else if (strcmp(param_name, "KEY_TYPE") == 0) {

			key_type = (hsm_key_type_t)parse_param_value(param_value_token,
							param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "FLAGS") == 0) {

			flags = (hsm_op_key_gen_flags_t)parse_param_value(param_value_token,
						param_name, &input_ctr, &invalid_read);

		}  else if (strcmp(param_name, "KEY_GROUP") == 0) {

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

		} else if (strcmp(param_name, "BIT_KEY_SZ") == 0) {
			bit_key_sz = (hsm_bit_key_sz_t)parse_param_value(param_value_token,
							param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "KEY_LIFECYCLE") == 0) {
			key_lifecycle = (hsm_key_lifecycle_t)parse_param_value(param_value_token,
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
		se_info("Key TV ID      : %u\n", key_tv_id);
		se_info("Key ID         : 0x%x\n", key_identifier);

		/* Getting Key Management handle for given Key Mgmt TV ID */
		key_mgmt_hdl = get_key_mgmt_hdl(key_mgmt_tv_id);

		if (expected_rsp_code == HSM_NO_ERROR &&
		    get_test_key_identifier(key_tv_id) != 0) {
			if (key_identifier != 0x0 &&
			    key_identifier != get_test_key_identifier(key_tv_id)) {
				se_info("\nFAILED: Key TV ID and Key Identifier pairing Invalid\n");
				goto out;
			}

			se_info("\nPersistent Key used, for Get Key Attributes:\n");
			ret = get_key_attributes(key_mgmt_hdl, get_test_key_identifier(key_tv_id));

			if (ret == HSM_NO_ERROR)
				test_status = 1;
			else
				test_status = 0;

		} else {
			se_info("\nKey MGMT TV ID : %u\n", key_mgmt_tv_id);
			se_info("Out Size       : %u\n", out_size);
			se_info("Key Type       : 0x%x\n", key_type);
			se_info("Flags          : 0x%x\n", flags);
			se_info("Key Group      : %u\n", key_group);
#ifdef PSA_COMPLIANT
			se_info("Key Lifetime   : 0x%x\n", key_lifetime);
			se_info("Key Usage      : 0x%x\n", key_usage);
			se_info("Permitted Algo : 0x%x\n", permitted_algo);
			se_info("Bit Key Size   : %u\n", bit_key_sz);
			se_info("Key Lifecycle  : 0x%x\n", key_lifecycle);
#else
			se_info("Key Info       : 0x%x\n", key_info);
#endif
			se_info("Expected Resp  : 0x%x\n\n", expected_rsp_code);

			se_info("\n\nNew Key Getting Generated:\n");
			ret = generate_key(key_mgmt_hdl,
					   key_type, key_group, flags,
					   out_key, out_size,
#ifndef PSA_COMPLIANT
					   key_info,
#else
					   key_lifetime, key_usage, permitted_algo,
					   bit_key_sz, key_lifecycle,
#endif
					   &key_identifier);

			if (ret == expected_rsp_code)
				test_status = 1;
			else
				test_status = 0;

			se_info("\nhsm_generate_key ret: 0x%x\n", ret);

			if (ret == HSM_NO_ERROR) {
				get_key_attributes(key_mgmt_hdl, key_identifier);

				save_test_key(key_tv_id, key_identifier, key_mgmt_tv_id,
					      key_group, key_type,
#ifdef PSA_COMPLIANT
					      bit_key_sz
#else
					      0
#endif
					      );

#ifdef PSA_COMPLIANT
				if (((flags & HSM_OP_KEY_GENERATION_FLAGS_STRICT_OPERATION) ==
					HSM_OP_KEY_GENERATION_FLAGS_STRICT_OPERATION) &&
					((key_lifetime & HSM_SE_KEY_STORAGE_PERSISTENT) ==
					HSM_SE_KEY_STORAGE_PERSISTENT))
					save_persistent_key(key_tv_id, key_identifier);
#endif
			}
		}
	}

	if (invalid_read == 1 || read == -1) {
		test_status = -1;

		/* EOF encountered before reading all param values. */
		if (read == -1)
			se_info("\nEOF reached. TEST_KGEN_END not detected.\n");

		se_info("\nSkipping this Test Case\n");
	}

out:
	if (out_key)
		free(out_key);

	if (line)
		free(line);

	return test_status;
}

void generate_key_test_tv(hsm_hdl_t key_store_hdl, FILE *fp, char *line,
			  uint8_t *tests_passed, uint8_t *tests_failed,
			  uint8_t *tests_invalid, uint8_t *tests_total)
{
	int8_t test_status = 0;
	static uint8_t tkgen_passed;
	static uint8_t tkgen_failed;
	static uint8_t tkgen_invalids;
	static uint8_t tkgen_total;

	int len = strlen(line);
	char *test_id = (char *)malloc(len * sizeof(char));

	strncpy(test_id, line, len);
	test_id[len - 1] = '\0';
	++tkgen_total;
	++(*tests_total);

	se_info("\n-----------------------------------------------\n");
	se_info("%s", line);
	se_info("-----------------------------------------------\n");

#ifdef PSA_COMPLIANT
	if (memcmp(line, "TEST_KGEN_PSA", 13) != 0) {
		se_info("Skipping Test: Test Case is NOT PSA_COMPLIANT\n");
		goto out;
	}
#else
	if (memcmp(line, "TEST_KGEN_NON_PSA", 17) != 0) {
		se_info("Skipping Test: Test Case is PSA_COMPLIANT\n");
		goto out;
	}
#endif
	test_status = prepare_and_run_genkey_test(fp);

	if (test_status == 1) {
		++tkgen_passed;
		++(*tests_passed);
		se_info("\nTEST RESULT: SUCCESS\n");
		printf("%s: SUCCESS\n", test_id);
	} else if (test_status == 0) {
		++tkgen_failed;
		++(*tests_failed);
		se_info("\nTEST RESULT: FAILED\n");
		printf("%s: FAILED\n", test_id);
	} else if (test_status == -1) {
		++tkgen_invalids;
		++(*tests_invalid);
		se_info("\nTEST_RESULT: INVALID\n");
		printf("%s: INVALID\n", test_id);
	}

	if (test_id)
		free(test_id);

out:

	se_info("\n------------------------------------------------------------------\n");
	se_info("TKGEN TESTS STATUS:: TOTAL: %u, SUCCESS: %u, FAILED: %u, INVALID: %u",
		tkgen_total, tkgen_passed, tkgen_failed, tkgen_invalids);
	se_info("\n------------------------------------------------------------------\n\n");

}
