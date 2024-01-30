// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#include <stdio.h>

#include "hsm_api.h"
#include "common.h"
#include "test_utils_tv.h"
#include "plat_utils.h"

static void data_storage_test_run(hsm_hdl_t key_store_hdl,
				  uint32_t data_id,
				  uint32_t data_size,
				  uint8_t *data,
				  hsm_op_data_storage_flags_t flags,
				  uint8_t exp_data_storage_hsm_rsp,
				  int8_t *test_status)
{
	hsm_err_t hsmret = HSM_GENERAL_ERROR;
	op_data_storage_args_t data_storage_args = {0};
	*test_status = TEST_STATUS_FAILED;

	data_storage_args.data_id = data_id;
	data_storage_args.data_size = data_size;
	data_storage_args.flags = flags;

	/* Store Data */
	if ((flags & HSM_OP_DATA_STORAGE_FLAGS_STORE)
		== HSM_OP_DATA_STORAGE_FLAGS_STORE) {

		data_storage_args.data = data;

		hsmret = hsm_data_ops(key_store_hdl, &data_storage_args);
		se_info("\nDATA STORAGE [STORE]: hsm_data_ops: 0x%x\n", hsmret);

		if (hsmret != exp_data_storage_hsm_rsp) {
			se_info("\nEXP_DATA_STORAGE_HSM_RESP didn't match Actual API Resp(0x%x)\n",
				hsmret);
			goto out;
		}

		*test_status = TEST_STATUS_SUCCESS;
	}

	/* Retrieve Data */
	if ((flags & HSM_OP_DATA_STORAGE_FLAGS_STORE)
		== HSM_OP_DATA_STORAGE_FLAGS_RETRIEVE) {

		data_storage_args.data = (uint8_t *) malloc(data_size*sizeof(uint8_t));

		if (data_storage_args.data == NULL) {
			se_info("\nError: Couldn't allocate memory for Retrieving Data\n");
			goto out;
		}

		memset(data_storage_args.data, 0, data_size*sizeof(uint8_t));

		hsmret = hsm_data_ops(key_store_hdl, &data_storage_args);
		se_info("\nDATA STORAGE [RETRIEVE]: hsm_data_ops: 0x%x\n", hsmret);

		if (hsmret != exp_data_storage_hsm_rsp) {
			se_info("\nEXP_DATA_STORAGE_HSM_RESP didn't match Actual API Resp(0x%x)\n",
				hsmret);
			goto out;
		}

		if (memcmp(data_storage_args.data, data, data_size) == 0) {
			se_info("Match Retrieved Data & Expected Data --> SUCCESS\n");
		} else {
			se_info("Match Retrieved Data & Expected Data --> FAILED\n");
			goto out;
		}

		*test_status = TEST_STATUS_SUCCESS;
	}

out:
	if (((flags & HSM_OP_DATA_STORAGE_FLAGS_STORE)
		== HSM_OP_DATA_STORAGE_FLAGS_RETRIEVE) && data_storage_args.data)
		free(data_storage_args.data);
}

static int8_t prepare_and_run_data_storage_test(hsm_hdl_t key_store_hdl, FILE *fp)
{
	uint8_t req_params_n = 5;
	uint8_t input_ctr = 0;
	uint8_t invalid_read = 0;
	uint8_t call_data_storage_test = -1;
	int8_t test_status = TEST_STATUS_FAILED;
	size_t len = 0;
	ssize_t read = 0;

	char *param_name = NULL;
	char *param_value_token = NULL;
	char *temp = NULL;
	char *line = NULL;

	uint8_t *data = NULL;
	uint32_t data_size = 0;
	uint32_t data_id = 0;
	hsm_op_data_storage_flags_t flags;
	uint8_t exp_data_storage_hsm_rsp = 0;

	while ((read = getline(&line, &len, fp)) != -1) {

		if (memcmp(line, "TEST_DATA_STORAGE_END", 13) == 0) {

			if (input_ctr == req_params_n) {
				call_data_storage_test = 1;
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


		if (strcmp(param_name, "DATA_ID") == 0) {

			data_id = (uint32_t)parse_param_value(param_value_token,
							param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "DATA_SIZE") == 0) {

			data_size = (uint32_t)parse_param_value(param_value_token,
						param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "DATA") == 0) {

			data = (uint8_t *) malloc(data_size * sizeof(uint8_t));

			memset(data, 0, data_size * sizeof(uint8_t));

			if (data == NULL) {
				invalid_read = 1;
				se_info("\nError: Couldn't allocate memory for %s\n", param_name);
				break;
			}

			parse_param_value_buffer(fp, &data, data_size, param_name,
									&input_ctr, &invalid_read);

		} else if (strcmp(param_name, "FLAGS") == 0) {

			flags = (hsm_op_data_storage_flags_t)parse_param_value(param_value_token,
							param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "EXP_DATA_STORAGE_HSM_RESP") == 0) {

			exp_data_storage_hsm_rsp  = (uint8_t)parse_param_value(param_value_token,
							param_name, &input_ctr, &invalid_read);

		}

		/* Invalid value for any param. */
		if (invalid_read == 1)
			break;
	}

	if (call_data_storage_test == 1) {

		se_info("Data ID            : 0x%x\n", data_id);
		se_info("Data Size          : %u\n", data_size);
		se_info("\nData               :\n");
		hexdump_bb(data, data_size);
		se_info("Flags              : 0x%x\n", flags);
		se_info("Expected Data Storage HSM Resp : 0x%x\n", exp_data_storage_hsm_rsp);
		se_info("----------------------------------------------------\n");

		data_storage_test_run(key_store_hdl, data_id, data_size, data, flags,
					exp_data_storage_hsm_rsp, &test_status);
	}

	if (invalid_read == 1 || read == -1) {
		test_status = TEST_STATUS_INVALID;

		/* EOF encountered before reading all param values. */
		if (read == -1)
			se_info("\nEOF reached. TEST_DATA_STORAGE_END not detected.\n");

		se_info("\nSkipping this Test Case\n");
	}

	if (data)
		free(data);

	if (line)
		free(line);

	return test_status;
}

void data_storage_test_tv(hsm_hdl_t key_store_hdl, FILE *fp, char *line,
			  uint8_t *tests_passed, uint8_t *tests_failed,
			  uint8_t *tests_invalid, uint8_t *tests_total)
{
	int8_t test_status = TEST_STATUS_FAILED;
	static uint8_t tdata_storage_passed;
	static uint8_t tdata_storage_failed;
	static uint8_t tdata_storage_invalids;
	static uint8_t tdata_storage_total;

	int len = strlen(line);
	char *test_id = (char *)malloc(len * sizeof(char));

	strncpy(test_id, line, len);
	test_id[len - 1] = '\0';
	++tdata_storage_total;
	++(*tests_total);

	se_info("\n-----------------------------------------------\n");
	se_info("%s", line);
	se_info("-----------------------------------------------\n");

#ifdef PSA_COMPLIANT
	if (memcmp(line, "TEST_DATA_STORAGE_PSA", 21) != 0) {
		se_info("Skipping Test: Test Case is NOT PSA_COMPLIANT\n");
		goto out;
	}
#else
	if (memcmp(line, "TEST_DATA_STORAGE_NON_PSA", 25) != 0) {
		se_info("Skipping Test: Test Case is PSA_COMPLIANT\n");
		goto out;
	}
#endif
	test_status = prepare_and_run_data_storage_test(key_store_hdl, fp);

	if (test_status == TEST_STATUS_SUCCESS) {
		se_info("\nTEST RESULT: SUCCESS\n");
		printf("%s: SUCCESS\n", test_id);
		++tdata_storage_passed;
		++(*tests_passed);
	} else if (test_status == TEST_STATUS_FAILED) {
		se_info("\nTEST RESULT: FAILED\n");
		printf("%s: FAILED\n", test_id);
		++tdata_storage_failed;
		++(*tests_failed);
	} else if (test_status == TEST_STATUS_INVALID) {
		se_info("\nTEST_RESULT: INVALID\n");
		printf("%s: INVALID\n", test_id);
		++tdata_storage_invalids;
		++(*tests_invalid);
	}

	if (test_id)
		free(test_id);

out:

	se_info("\n------------------------------------------------------------------\n");
	se_info("TDATA_STORAGE TESTS STATUS:: TOTAL: %u, SUCCESS: %u, FAILED: %u, INVALID: %u",
		tdata_storage_total, tdata_storage_passed, tdata_storage_failed,
		tdata_storage_invalids);
	se_info("\n------------------------------------------------------------------\n\n");

}

