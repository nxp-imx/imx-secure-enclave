// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#include <stdio.h>

#include "hsm_api.h"
#include "common.h"
#include "test_utils_tv.h"
#include "plat_utils.h"

//HASH One shot operation test
static void hash_test_run(hsm_hash_algo_t hash_algo,
			  hsm_hash_svc_flags_t flags,
			  uint32_t input_size,
			  uint8_t *input_data,
			  uint32_t output_size,
			  uint32_t exp_output_size,
			  uint32_t exp_output_buf_size,
			  uint8_t *exp_output_buf,
			  uint8_t exp_hash_hsm_rsp,
			  int8_t *test_status)
{
	hsm_err_t hsmret = HSM_GENERAL_ERROR;
	hsm_hdl_t hash_sess = get_hsm_session_hdl();
	op_hash_one_go_args_t hash_args = {0};
	*test_status = TEST_STATUS_FAILED;

	hash_args.algo = hash_algo;
	hash_args.svc_flags = flags;
	hash_args.input_size = input_size;
	hash_args.input = input_data;
	hash_args.output_size = output_size;
	hash_args.output = (uint8_t *) malloc(output_size*sizeof(uint8_t));

	if (hash_args.output == NULL) {
		printf("\nError: Couldn't allocate memory for Output Digest\n");
		goto out;
	}

	memset(hash_args.output, 0, output_size*sizeof(uint8_t));

	hsmret = hsm_do_hash(hash_sess, &hash_args);
	se_info("\nHASH: hsm_do_hash ret: 0x%x\n", hsmret);

	if (hsmret != exp_hash_hsm_rsp) {
		se_info("\nEXP_HASH_HSM_RESP didn't match HASH op Resp(0x%x)\n", hsmret);
		goto out;
	}

#ifdef PSA_COMPLIANT
	/*
	 * The Expected output size for digest buffer in HSM HASH API op args,
	 * is only valid for cases HSM_NO_ERROR, HSM_OUT_TOO_SMALL, HSM_GENERAL_ERROR.
	 */

	if (hsmret == HSM_NO_ERROR || hsmret == HSM_OUT_TOO_SMALL ||
		hsmret == HSM_GENERAL_ERROR) {

		if (hash_args.exp_output_size != exp_output_size) {
			printf("\nEXP_OUTPUT_SIZE didn't match HASH API Resp output size %u\n",
					hash_args.exp_output_size);
			goto out;
		}
	}
#endif

	if (hsmret == HSM_NO_ERROR) {
#ifdef PSA_COMPLIANT
		/*
		 * If Output Size (input param provided) is equal or greater than
		 * required, then expected/correct Output digest size is returned
		 * with HSM_NO_ERROR
		 */
		output_size = hash_args.exp_output_size;
#endif
		if ((output_size == exp_output_buf_size) &&
			(memcmp(exp_output_buf, hash_args.output, output_size) == 0)) {
			se_info("Match Expected Output & Actual Output --> SUCCESS\n");
		} else {
			se_info("Match Expected Output & Actual Output --> FAILURE\n");
			goto out;
		}
	}

	*test_status = TEST_STATUS_SUCCESS;
out:
	if (hash_args.output)
		free(hash_args.output);
}

static int8_t prepare_and_run_hash_test(FILE *fp)
{
#ifdef PSA_COMPLIANT
	uint8_t req_params_n = 12;
#else
	uint8_t req_params_n = 9;
#endif
	uint8_t input_ctr = 0;
	uint8_t invalid_read = 0;
	uint8_t call_hash_test = -1;
	int8_t test_status = TEST_STATUS_FAILED;
	size_t len = 0;
	ssize_t read = 0;

	char *param_name = NULL;
	char *param_value_token = NULL;
	char *temp = NULL;
	char *line = NULL;

	hsm_hash_algo_t hash_algo;
	hsm_hash_svc_flags_t flags;
#ifdef PSA_COMPLIANT
	uint8_t *msb;
	uint8_t *ctx;
	uint16_t ctx_size;
	uint16_t exp_ctx_size;
#endif
	uint32_t input_size = 0;
	uint32_t output_size = 0;
	uint8_t *input_data = NULL;
	/*
	 * exp_output_size: Expected Output Size, for testing the Output Size
	 * returned by FW in HASH API Resp for incorrect output size provided
	 * in input params
	 */
	uint32_t exp_output_size = 0;
	uint32_t exp_output_buf_size = 0;
	uint8_t *exp_output_buf = NULL;
	uint8_t exp_hash_hsm_rsp = 0;

	while ((read = getline(&line, &len, fp)) != -1) {

		if (memcmp(line, "TEST_HASH_END", 13) == 0) {

			if (input_ctr == req_params_n) {
				call_hash_test = 1;
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


		if (strcmp(param_name, "HASH_ALGO") == 0) {

			hash_algo = (uint32_t)parse_param_value(param_value_token,
							param_name, &input_ctr, &invalid_read);

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

		} else if (strcmp(param_name, "FLAGS") == 0) {
			flags = (hsm_hash_svc_flags_t)parse_param_value(param_value_token,
									param_name,
									&input_ctr,
									&invalid_read);
#ifdef PSA_COMPLIANT
		} else if (strcmp(param_name, "CTX_SIZE") == 0) {
			ctx_size = (uint16_t)parse_param_value(param_value_token,
							       param_name,
							       &input_ctr,
							       &invalid_read);

		} else if (strcmp(param_name, "INPUT_CTX") == 0) {
			ctx = (uint8_t *)malloc(ctx_size * sizeof(uint8_t));
			memset(ctx, 0, ctx_size * sizeof(uint8_t));

			if (!ctx) {
				invalid_read = 1;
				printf("\nError: Couldn't allocate memory for %s\n",
				       param_name);
				break;
			}

			parse_param_value_buffer(fp, &ctx, ctx_size,
						 param_name, &input_ctr,
						 &invalid_read);

		} else if (strcmp(param_name, "EXP_CTX_SIZE") == 0) {
			exp_ctx_size = (uint16_t)parse_param_value(param_value_token,
								   param_name,
								   &input_ctr,
								   &invalid_read);
#endif
		} else if (strcmp(param_name, "EXP_OUTPUT_SIZE") == 0) {

			exp_output_size = (uint32_t)parse_param_value(param_value_token,
							param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "EXP_OUTPUT_BUF") == 0) {

			exp_output_buf_size = (uint32_t)parse_param_value(param_value_token,
							param_name, &input_ctr, &invalid_read);

			if (invalid_read == 1)
				break;

			exp_output_buf = (uint8_t *)malloc(exp_output_buf_size*sizeof(uint8_t));

			if (exp_output_buf == NULL) {
				invalid_read = 1;
				printf("\nError: Couldn't allocate memory for %s\n", param_name);
				break;
			}

			parse_param_value_buffer(fp, &exp_output_buf, exp_output_buf_size,
							param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "EXP_HASH_HSM_RESP") == 0) {

			exp_hash_hsm_rsp  = (uint8_t)parse_param_value(param_value_token,
							param_name, &input_ctr, &invalid_read);

		}

		/* Invalid value for any param. */
		if (invalid_read == 1)
			break;
	}

	if (call_hash_test == 1) {

		se_info("HASH Algo          : 0x%x\n", hash_algo);
#ifdef PSA_COMPLIANT
		se_info("Flags              : 0x%x\n", flags);
		se_info("Context Size       : %u\n", ctx_size);
		se_info("\nInput Context      :\n");
		hexdump_bb(ctx, ctx_size);
#endif
		se_info("Input Size         : %u\n", input_size);
		se_info("\nInput Data        :\n");
		hexdump_bb(input_data, input_size);
		se_info("Output Size          : %u\n", output_size);
#ifdef PSA_COMPLIANT
		se_info("Expected Context Size : %u\n", exp_ctx_size);
#endif
		se_info("Expected Output Size : %u\n", exp_output_size);
		se_info("\nExpected Output Buffer size : %u\n", exp_output_buf_size);
		se_info("\nExpected Output Buffer :\n");
		hexdump_bb(exp_output_buf, exp_output_buf_size);
		se_info("Expected HASH HSM Resp : 0x%x\n", exp_hash_hsm_rsp);
		se_info("----------------------------------------------------\n");

		if (!(flags & HSM_HASH_FLAG_ALLOWED)) {
			invalid_read = 1;
			printf("\nInvalid HASH op flag value. Not Allowed.\n");
			goto exit;
		}

		//HASH test involving context not supported yet.
		switch (flags) {
		case HSM_HASH_FLAG_ONE_SHOT:
			hash_test_run(hash_algo, flags, input_size,
				      input_data, output_size, exp_output_size,
				      exp_output_buf_size, exp_output_buf,
				      exp_hash_hsm_rsp, &test_status);
			break;
		default:
			invalid_read = 1;
			printf("\nTest not supported through test vectors yet.\n");
		}
	}

exit:
	if (invalid_read == 1 || read == -1) {
		test_status = TEST_STATUS_INVALID;

		/* EOF encountered before reading all param values. */
		if (read == -1)
			printf("\nEOF reached. TEST_HASH_END not detected.\n");

		printf("\nSkipping this Test Case\n");
	}

	if (input_data)
		free(input_data);

	if (exp_output_buf)
		free(exp_output_buf);

	if (line)
		free(line);

	return test_status;
}

void hash_test_tv(FILE *fp, char *line, uint8_t *tests_passed, uint8_t *tests_failed,
		  uint8_t *tests_invalid, uint8_t *tests_total)
{
	int8_t test_status = TEST_STATUS_FAILED;
	static uint8_t thash_passed;
	static uint8_t thash_failed;
	static uint8_t thash_invalids;
	static uint8_t thash_total;

	int len = strlen(line);
	char *test_id = (char *)malloc(len * sizeof(char));

	strncpy(test_id, line, len);
	test_id[len - 1] = '\0';
	++thash_total;
	++(*tests_total);

	se_info("\n-----------------------------------------------\n");
	se_info("%s", line);
	se_info("-----------------------------------------------\n");

#ifdef PSA_COMPLIANT
	if (memcmp(line, "TEST_HASH_PSA", 13) != 0) {
		printf("Skipping Test: Test Case is NOT PSA_COMPLIANT\n");
		goto out;
	}
#else
	if (memcmp(line, "TEST_HASH_NON_PSA", 17) != 0) {
		printf("Skipping Test: Test Case is PSA_COMPLIANT\n");
		goto out;
	}
#endif
	test_status = prepare_and_run_hash_test(fp);

	if (test_status == TEST_STATUS_SUCCESS) {
		se_info("\nTEST RESULT: SUCCESS\n");
		printf("%s: SUCCESS\n", test_id);
		++thash_passed;
		++(*tests_passed);
	} else if (test_status == TEST_STATUS_FAILED) {
		se_info("\nTEST RESULT: FAILED\n");
		printf("%s: FAILED\n", test_id);
		++thash_failed;
		++(*tests_failed);
	} else if (test_status == TEST_STATUS_INVALID) {
		se_info("\nTEST_RESULT: INVALID\n");
		printf("%s: INVALID\n", test_id);
		++thash_invalids;
		++(*tests_invalid);
	}

	if (test_id)
		free(test_id);

out:

	se_info("\n------------------------------------------------------------------\n");
	se_info("THASH TESTS STATUS:: TOTAL: %u, SUCCESS: %u, FAILED: %u, INVALID: %u",
		thash_total, thash_passed, thash_failed, thash_invalids);
	se_info("\n------------------------------------------------------------------\n\n");

}

