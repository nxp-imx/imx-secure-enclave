// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#include <stdio.h>

#include "hsm_api.h"
#include "common.h"
#include "test_utils_tv.h"
#include "plat_utils.h"

static uint8_t is_buff_empty(uint8_t *data_buff, uint32_t size)
{
	uint8_t res = 0;

	for (uint32_t i = 0; i < size; i++)
		res |= data_buff[i];

	return res;
}

static hsm_err_t rng_test_run(uint32_t random_size)
{
	hsm_err_t hsmret = HSM_GENERAL_ERROR;
	hsm_hdl_t sess_hdl = get_hsm_session_hdl();
	op_get_random_args_t rng_args = {0};
	uint8_t *output_buffer = NULL;

	memset(&rng_args, 0, sizeof(rng_args));

	output_buffer = (uint8_t *)malloc(random_size * sizeof(uint8_t));

	if (!output_buffer) {
		se_err("\nError: Couldn't allocate memory for RNG\n");
		goto out;
	}

	memset(output_buffer, 0, random_size);

	rng_args.random_size = random_size;
	rng_args.output = output_buffer;

	hsmret = hsm_do_rng(sess_hdl, &rng_args);

	if (hsmret != HSM_NO_ERROR)
		goto out;

	if (!is_buff_empty(output_buffer, random_size))
		printf("Fail: Output buffer is Empty\n");
out:
	if (output_buffer)
		free(output_buffer);

	return hsmret;
}

static int8_t prepare_and_run_rng_test(FILE *fp)
{
	hsm_err_t ret = HSM_GENERAL_ERROR;

	uint8_t req_params_n = 2;
	uint8_t input_ctr = 0;
	uint8_t invalid_read = 0;
	uint8_t call_rng_test = -1;
	int8_t test_status = TEST_STATUS_FAILED;
	size_t len = 0;
	ssize_t read = 0;

	char *param_name = NULL;
	char *param_value_token = NULL;
	char *temp = NULL;
	char *line = NULL;

	uint32_t output_buffer = 0;
	uint32_t random_size = 0;
	uint32_t expected_rsp_code = 0;

	while ((read = getline(&line, &len, fp)) != -1) {
		if (memcmp(line, "TEST_RNG_END", 12) == 0) {
			if (input_ctr == req_params_n) {
				call_rng_test = 1;
			} else {
				/* Invalid Test case due to less no. of params
				 * than required
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

		if (strcmp(param_name, "RANDOM_SIZE") == 0) {
			random_size = (uint32_t)parse_param_value(param_value_token,
						param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "EXPECTED_HSM_RESP") == 0) {
			expected_rsp_code  = (uint8_t)parse_param_value(param_value_token,
						param_name, &input_ctr, &invalid_read);
		}

		/* Invalid value for any param. */
		if (invalid_read == 1)
			break;
	}

	if (call_rng_test == 1) {
		se_info("Random Size                   : %u\n", random_size);
		se_info("Expected HSM Resp             : 0x%x\n", expected_rsp_code);

		se_info("----------------------------------------------------\n");

		ret = rng_test_run(random_size);

		if (ret == expected_rsp_code)
			test_status = TEST_STATUS_SUCCESS;
		else
			test_status = TEST_STATUS_FAILED;
	}

	if (invalid_read == 1 || read == -1) {
		test_status = TEST_STATUS_INVALID;

		/* EOF encountered before reading all param values. */
		if (read == -1)
			se_info("\nEOF reached. TEST_RNG_END not detected.\n");
	}

out:
	if (line)
		free(line);

	return test_status;
}

void rng_test_tv(FILE *fp, char *line, uint16_t *tests_passed,
		 uint16_t *tests_failed, uint16_t *tests_invalid,
		 uint16_t *tests_total)
{
	int8_t test_status = TEST_STATUS_FAILED;
	static uint16_t trng_passed;
	static uint16_t trng_failed;
	static uint16_t trng_invalids;
	static uint16_t trng_total;

	int len = strlen(line);
	char *test_id = (char *)malloc(len * sizeof(char));

	snprintf(test_id, len, "%s", line);
	++trng_total;
	++(*tests_total);

	se_info("\n-----------------------------------------------\n");
	se_info("%s", line);
	se_info("-----------------------------------------------\n");

#ifdef PSA_COMPLIANT
	if (memcmp(line, "TEST_RNG_PSA", 12) != 0) {
		se_info("Skipping Test: Test Case is NOT PSA_COMPLIANT\n");
		goto out;
	}
#else
	if (memcmp(line, "TEST_RNG_NON_PSA", 16) != 0) {
		se_info("Skipping Test: Test Case is PSA_COMPLIANT\n");
		goto out;
	}
#endif
	test_status = prepare_and_run_rng_test(fp);

	if (test_status == TEST_STATUS_SUCCESS) {
		++trng_passed;
		++(*tests_passed);
		printf("%s: SUCCESS\n", test_id);
	} else if (test_status == TEST_STATUS_FAILED) {
		++trng_failed;
		++(*tests_failed);
		printf("%s: FAILED\n", test_id);
	} else if (test_status == TEST_STATUS_INVALID) {
		++trng_invalids;
		++(*tests_invalid);
		printf("%s: INVALID\n", test_id);
	} else if (test_status == TEST_STATUS_SKIPPED) {
		--trng_total;
		--(*tests_total);
		printf("%s: SKIPPED\n", test_id);
	}

out:
	if (test_id)
		free(test_id);

	se_info("\n------------------------------------------------------------------\n");
	se_info("TRNG TESTS STATUS:: TOTAL: %u, SUCCESS: %u, FAILED: %u, INVALID: %u",
		trng_total, trng_passed, trng_failed, trng_invalids);
	se_info("\n------------------------------------------------------------------\n\n");
}

