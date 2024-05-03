// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#include <stdio.h>
#include <string.h>

#include "common.h"
#include "hsm_api.h"
#include "test_utils_tv.h"
#include "plat_utils.h"

#ifdef PSA_COMPLIANT
static void cipher_test_run(hsm_hdl_t key_store_hdl,
			    hsm_hdl_t key_mgmt_hdl,
			    uint32_t data_buff1_size,
			    uint32_t data_buff2_size,
			    uint8_t *data_buff1,
			    uint16_t key_buff1_size,
			    uint16_t key_buff2_pub_size,
			    uint16_t key_buff2_priv_size,
			    uint8_t *key_buff1,
			    uint8_t *key_buff2_pub,
			    uint8_t *key_buff2_priv,
			    hsm_op_gc_acrypto_algo_t algorithm,
			    hsm_gc_acrypto_op_mode_t op_mode,
			    hsm_bit_key_sz_t bit_key_sz,
			    hsm_op_gc_acrypto_flags_t flags,
			    uint8_t *rsa_label,
			    uint16_t rsa_label_size,
			    uint8_t rsa_salt_len,
			    uint32_t exp_plaintext_len,
			    hsm_gc_acrypto_verification_status_t exp_verification_status,
			    int8_t *test_status)
{
	op_gc_acrypto_args_t gc_acrypto_args = {0};
	hsm_gc_acrypto_verification_status_t verification_status;
	hsm_err_t hsmret = HSM_GENERAL_ERROR;
	uint8_t *ciphertext = NULL;
	uint8_t *deciphered_data = NULL;
	hsm_hdl_t hsm_session_hdl = get_hsm_session_hdl();
	*test_status = TEST_STATUS_FAILED;

	ciphertext = (uint8_t *)malloc(data_buff2_size * sizeof(uint8_t));

	if (!ciphertext) {
		se_err("\nError: Couldn't allocate memory for Ciphertext\n");
		goto out;
	}

	deciphered_data = (uint8_t *)malloc(data_buff1_size * sizeof(uint8_t));

	if (!deciphered_data) {
		se_err("\nError: Couldn't allocate memory for deciphered Data\n");
		goto out;
	}

	memset(ciphertext, 0, sizeof(ciphertext));
	memset(deciphered_data, 0, sizeof(deciphered_data));

	/* ENCRYPT operation */
	gc_acrypto_args.data_buff1_size = data_buff1_size;
	gc_acrypto_args.data_buff2_size = data_buff2_size;
	gc_acrypto_args.data_buff1 = data_buff1;
	gc_acrypto_args.data_buff2 = ciphertext;
	gc_acrypto_args.key_buff1_size = key_buff1_size;
	gc_acrypto_args.key_buff2_size = key_buff2_pub_size;
	gc_acrypto_args.key_buff1 = key_buff1;
	gc_acrypto_args.key_buff2 = key_buff2_pub;
	gc_acrypto_args.algorithm = algorithm;
	gc_acrypto_args.op_mode = op_mode;
	gc_acrypto_args.flags = flags;
	gc_acrypto_args.bit_key_sz = bit_key_sz;
	gc_acrypto_args.rsa_label = rsa_label;
	gc_acrypto_args.rsa_label_size = rsa_label_size;
	gc_acrypto_args.rsa_salt_len = rsa_salt_len;

	hsmret = hsm_gc_acrypto(hsm_session_hdl, &gc_acrypto_args);

	if (hsmret != HSM_NO_ERROR) {
		se_info("\nGC ACRYPTO: hsm_gc_acrypto ret: 0x%x\n", hsmret);
		goto out;
	}

	/* DECRYPT operation */
	gc_acrypto_args.data_buff1_size = data_buff1_size;
	gc_acrypto_args.data_buff2_size = data_buff2_size;
	gc_acrypto_args.data_buff1 = deciphered_data;
	gc_acrypto_args.data_buff2 = ciphertext;
	gc_acrypto_args.key_buff1_size = key_buff1_size;
	gc_acrypto_args.key_buff2_size = key_buff2_priv_size;
	gc_acrypto_args.key_buff1 = key_buff1;
	gc_acrypto_args.key_buff2 = key_buff2_priv;
	gc_acrypto_args.algorithm = algorithm;
	gc_acrypto_args.op_mode = HSM_GC_ACRYPTO_OP_MODE_DECRYPT;
	gc_acrypto_args.flags = flags;
	gc_acrypto_args.bit_key_sz = bit_key_sz;
	gc_acrypto_args.rsa_label = rsa_label;
	gc_acrypto_args.rsa_label_size = rsa_label_size;
	gc_acrypto_args.rsa_salt_len = rsa_salt_len;

	hsmret = hsm_gc_acrypto(hsm_session_hdl, &gc_acrypto_args);

	if (hsmret != HSM_NO_ERROR) {
		se_info("\nGC ACRYPTO: hsm_gc_acrypto ret: 0x%x\n", hsmret);
		goto out;
	}

	if (memcmp(data_buff1, deciphered_data, sizeof(data_buff1)) != 0)
		printf("\nDecrypted Text doesn't match the Plaintext [FAIL]\n");

	*test_status = TEST_STATUS_SUCCESS;
out:
	if (ciphertext)
		free(ciphertext);

	if (deciphered_data)
		free(deciphered_data);
}

static void sign_test_run(hsm_hdl_t key_store_hdl,
			  hsm_hdl_t key_mgmt_hdl,
			  uint32_t data_buff1_size,
			  uint32_t data_buff2_size,
			  uint8_t *data_buff1,
			  uint16_t key_buff1_size,
			  uint16_t key_buff2_pub_size,
			  uint16_t key_buff2_priv_size,
			  uint8_t *key_buff1,
			  uint8_t *key_buff2_pub,
			  uint8_t *key_buff2_priv,
			  hsm_op_gc_acrypto_algo_t algorithm,
			  hsm_gc_acrypto_op_mode_t op_mode,
			  hsm_bit_key_sz_t bit_key_sz,
			  hsm_op_gc_acrypto_flags_t flags,
			  uint8_t *rsa_label,
			  uint16_t rsa_label_size,
			  uint8_t rsa_salt_len,
			  uint32_t exp_plaintext_len,
			  hsm_gc_acrypto_verification_status_t exp_verification_status,
			  int8_t *test_status)
{
	op_gc_acrypto_args_t gc_acrypto_args = {0};
	hsm_gc_acrypto_verification_status_t verification_status;
	hsm_err_t hsmret = HSM_GENERAL_ERROR;
	uint8_t *signature = NULL;
	hsm_hdl_t hsm_session_hdl = get_hsm_session_hdl();
	*test_status = TEST_STATUS_FAILED;

	signature = (uint8_t *)malloc(data_buff2_size * sizeof(uint8_t));

	if (!signature) {
		se_err("\nError: Couldn't allocate memory for Signature\n");
		goto out;
	}

	memset(signature, 0, data_buff2_size);

	/*  RSA Signature Generation */
	gc_acrypto_args.data_buff1_size = data_buff1_size;
	gc_acrypto_args.data_buff2_size = data_buff2_size;
	gc_acrypto_args.data_buff1 = data_buff1;
	gc_acrypto_args.data_buff2 = signature;
	gc_acrypto_args.key_buff1_size = key_buff1_size;
	gc_acrypto_args.key_buff2_size = key_buff2_priv_size;
	gc_acrypto_args.key_buff1 = key_buff1;
	gc_acrypto_args.key_buff2 = key_buff2_priv;
	gc_acrypto_args.algorithm = algorithm;
	gc_acrypto_args.op_mode = op_mode;
	gc_acrypto_args.flags = flags;
	gc_acrypto_args.bit_key_sz = bit_key_sz;
	gc_acrypto_args.rsa_label = rsa_label;
	gc_acrypto_args.rsa_label_size = rsa_label_size;
	gc_acrypto_args.rsa_salt_len = rsa_salt_len;

	hsmret = hsm_gc_acrypto(hsm_session_hdl, &gc_acrypto_args);

	if (hsmret != HSM_NO_ERROR) {
		se_info("\nGC ACRYPTO: hsm_gc_acrypto ret: 0x%x\n", hsmret);
		goto out;
	}

	/*  RSA Signature Verification */
	gc_acrypto_args.data_buff1_size = data_buff1_size;
	gc_acrypto_args.data_buff2_size = data_buff2_size;
	gc_acrypto_args.data_buff1 = data_buff1;
	gc_acrypto_args.data_buff2 = signature;
	gc_acrypto_args.key_buff1_size = key_buff1_size;
	gc_acrypto_args.key_buff2_size = key_buff2_pub_size;
	gc_acrypto_args.key_buff1 = key_buff1;
	gc_acrypto_args.key_buff2 = key_buff2_pub;
	gc_acrypto_args.algorithm = algorithm;
	gc_acrypto_args.op_mode = HSM_GC_ACRYPTO_OP_MODE_SIGN_VER;
	gc_acrypto_args.flags = flags;
	gc_acrypto_args.bit_key_sz = bit_key_sz;
	gc_acrypto_args.rsa_label = rsa_label;
	gc_acrypto_args.rsa_label_size = rsa_label_size;
	gc_acrypto_args.rsa_salt_len = rsa_salt_len;

	hsmret = hsm_gc_acrypto(hsm_session_hdl, &gc_acrypto_args);

	if (hsmret != HSM_NO_ERROR) {
		se_info("\nGC ACRYPTO: hsm_gc_acrypto ret: 0x%x\n", hsmret);
		goto out;
	}

	if (gc_acrypto_args.verification_status != exp_verification_status) {
		se_info("\nEXP_VERIFICATION_STATUS didn't match Actual status(0x%x)\n",
			gc_acrypto_args.verification_status);
		goto out;
	}

	*test_status = TEST_STATUS_SUCCESS;
out:
	if (signature)
		free(signature);
}

static int8_t prepare_and_run_gc_acrypto_test(hsm_hdl_t key_store_hdl, FILE *fp)
{
	hsm_err_t ret = HSM_GENERAL_ERROR;
	hsm_hdl_t key_mgmt_hdl = 0;

	uint8_t req_params_n = 19;
	uint8_t input_ctr = 0;
	uint8_t invalid_read = 0;
	uint8_t call_gc_acrypto_test = -1;
	int8_t test_status = TEST_STATUS_FAILED;
	size_t len = 0;
	ssize_t read = 0;

	char *param_name = NULL;
	char *param_value_token = NULL;
	char *temp = NULL;
	char *line = NULL;

	uint32_t key_mgmt_tv_id = 0;

	uint8_t *data_buff1 = 0;
	hsm_op_gc_acrypto_algo_t algorithm;
	hsm_gc_acrypto_op_mode_t op_mode;
	hsm_bit_key_sz_t bit_key_sz;
	hsm_op_gc_acrypto_flags_t flags;
	uint32_t data_buff1_size;
	uint32_t data_buff2_size;
	uint8_t *key_buff1;
	uint8_t *key_buff2_pub;
	uint8_t *key_buff2_priv;
	uint16_t key_buff1_size;
	uint16_t key_buff2_pub_size;
	uint16_t key_buff2_priv_size;
	uint8_t *rsa_label;
	uint16_t rsa_label_size;
	uint8_t rsa_salt_len;
	uint32_t exp_plaintext_len;
	hsm_gc_acrypto_verification_status_t exp_verification_status;

	while ((read = getline(&line, &len, fp)) != -1) {
		if (memcmp(line, "TEST_GC_ACRYPTO_END", 19) == 0) {
			if (input_ctr == req_params_n) {
				call_gc_acrypto_test = 1;
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
			key_mgmt_tv_id = (uint32_t)parse_param_value
					 (param_value_token, param_name, &input_ctr,
					  &invalid_read);

		} else if (strcmp(param_name, "DATA_BUFF1_SIZE") == 0) {
			data_buff1_size = (uint32_t)parse_param_value
					  (param_value_token, param_name, &input_ctr,
					   &invalid_read);

		} else if (strcmp(param_name, "DATA_BUFF2_SIZE") == 0) {
			data_buff2_size = (uint32_t)parse_param_value
					  (param_value_token, param_name, &input_ctr,
					   &invalid_read);

		} else if (strcmp(param_name, "DATA_BUFF1") == 0) {
			data_buff1 = (uint8_t *)malloc(data_buff1_size * sizeof(uint8_t));

			if (!data_buff1) {
				invalid_read = 1;
				se_info("\nError: Couldn't allocate");
				se_info("memory for %s\n", param_name);
				break;
			}

			parse_param_value_buffer(fp, &data_buff1, data_buff1_size,
						 param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "KEY_BUFF1_SIZE") == 0) {
			key_buff1_size = (uint16_t)parse_param_value
					 (param_value_token, param_name, &input_ctr,
					  &invalid_read);

		} else if (strcmp(param_name, "KEY_BUFF2_PUB_SIZE") == 0) {
			key_buff2_pub_size = (uint16_t)parse_param_value
					     (param_value_token, param_name, &input_ctr,
					      &invalid_read);

		} else if (strcmp(param_name, "KEY_BUFF2_PRIV_SIZE") == 0) {
			key_buff2_priv_size = (uint16_t)parse_param_value
					      (param_value_token, param_name, &input_ctr,
					       &invalid_read);

		} else if (strcmp(param_name, "KEY_BUFF1") == 0) {
			key_buff1 = (uint8_t *)malloc(key_buff1_size * sizeof(uint8_t));

			if (!key_buff1) {
				invalid_read = 1;
				se_info("\nError: Couldn't allocate");
				se_info("memory for %s\n", param_name);
				break;
			}

			parse_param_value_buffer(fp, &key_buff1, key_buff1_size,
						 param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "KEY_BUFF2_PUB") == 0) {
			key_buff2_pub = (uint8_t *)malloc
					(key_buff2_pub_size * sizeof(uint8_t));

			if (!key_buff2_pub) {
				invalid_read = 1;
				se_info("\nError: Couldn't allocate");
				se_info("memory for %s\n", param_name);
				break;
			}

			parse_param_value_buffer(fp, &key_buff2_pub, key_buff2_pub_size,
						 param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "KEY_BUFF2_PRIV") == 0) {
			key_buff2_priv = (uint8_t *)malloc
					 (key_buff2_priv_size * sizeof(uint8_t));

			if (!key_buff2_priv) {
				invalid_read = 1;
				se_info("\nError: Couldn't allocate");
				se_info(" memory for %s\n", param_name);
				break;
			}

			parse_param_value_buffer(fp, &key_buff2_priv, key_buff2_priv_size,
						 param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "ALGORITHM") == 0) {
			algorithm = (hsm_op_gc_acrypto_algo_t)parse_param_value
				    (param_value_token, param_name, &input_ctr,
				     &invalid_read);

		} else if (strcmp(param_name, "OPERATION_MODE") == 0) {
			op_mode = (hsm_gc_acrypto_op_mode_t)parse_param_value
				  (param_value_token, param_name, &input_ctr,
				   &invalid_read);

		} else if (strcmp(param_name, "BIT_KEY_SZ") == 0) {
			bit_key_sz = (hsm_bit_key_sz_t)parse_param_value
				     (param_value_token, param_name, &input_ctr,
				      &invalid_read);

		} else if (strcmp(param_name, "FLAGS") == 0) {
			flags = (hsm_op_gc_acrypto_flags_t)parse_param_value
				(param_value_token, param_name, &input_ctr,
				 &invalid_read);

		} else if (strcmp(param_name, "RSA_LABEL") == 0) {
			rsa_label = (uint8_t *)malloc(rsa_label_size * sizeof(uint8_t));

			if (!rsa_label) {
				invalid_read = 1;
				se_info("\nError: Couldn't allocate");
				se_info(" memory for %s\n", param_name);
				break;
			}

			parse_param_value_buffer(fp, &rsa_label, rsa_label_size,
						 param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "RSA_LABEL_SIZE") == 0) {
			rsa_label_size = (uint16_t)parse_param_value(param_value_token,
					param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "RSA_SALT_LEN") == 0) {
			rsa_salt_len = (uint8_t)parse_param_value(param_value_token,
					param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "EXP_PLAINTEXT_SIZE") == 0) {
			exp_plaintext_len = (uint32_t)parse_param_value(param_value_token,
						param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "EXP_VERIFICATION_STATUS") == 0) {
			exp_verification_status = (hsm_gc_acrypto_verification_status_t)
				parse_param_value(param_value_token, param_name,
						  &input_ctr, &invalid_read);
		}

		/* Invalid value for any param. */
		if (invalid_read == 1)
			break;
	}

	if (call_gc_acrypto_test == 1) {
		key_mgmt_hdl = get_key_mgmt_hdl(key_mgmt_tv_id);
		if (op_mode == HSM_GC_ACRYPTO_OP_MODE_ENCRYPT) {
			cipher_test_run(key_store_hdl, key_mgmt_hdl, data_buff1_size,
					data_buff2_size, data_buff1, key_buff1_size,
					key_buff2_pub_size, key_buff2_priv_size,
					key_buff1, key_buff2_pub, key_buff2_priv,
					algorithm, op_mode, bit_key_sz, flags,
					rsa_label, rsa_label_size, rsa_salt_len,
					exp_plaintext_len, exp_verification_status,
					&test_status);
		} else if (op_mode == HSM_GC_ACRYPTO_OP_MODE_SIGN_GEN) {
			sign_test_run(key_store_hdl, key_mgmt_hdl, data_buff1_size,
				      data_buff2_size, data_buff1, key_buff1_size,
				      key_buff2_pub_size, key_buff2_priv_size, key_buff1,
				      key_buff2_pub, key_buff2_priv, algorithm,
				      op_mode, bit_key_sz, flags, rsa_label,
				      rsa_label_size, rsa_salt_len, exp_plaintext_len,
				      exp_verification_status, &test_status);
		}
	}

	if (invalid_read == 1 || read == -1) {
		test_status = TEST_STATUS_INVALID;

		/* EOF encountered before reading all param values. */
		if (read == -1)
			se_info("\nEOF reached. TEST_GC_ACRYPTO_END not detected.\n");
	}

	if (data_buff1)
		free(data_buff1);

	if (key_buff1)
		free(key_buff1);

	if (key_buff2_pub)
		free(key_buff2_pub);

	if (key_buff2_priv)
		free(key_buff2_priv);

	if (rsa_label)
		free(rsa_label);

	if (line)
		free(line);

	return test_status;
}

void gc_acrypto_test_tv(hsm_hdl_t key_store_hdl, FILE *fp, char *line,
			uint16_t *tests_passed, uint16_t *tests_failed,
			uint16_t *tests_invalid, uint16_t *tests_total)
{
	int8_t test_status = TEST_STATUS_FAILED;
	static uint16_t tgc_acrypto_passed;
	static uint16_t tgc_acrypto_failed;
	static uint16_t tgc_acrypto_invalids;
	static uint16_t tgc_acrypto_total;

	int len = strlen(line);
	char *test_id = (char *)malloc(len * sizeof(char));

	snprintf(test_id, len, "%s", line);

	++tgc_acrypto_total;
	++(*tests_total);

	se_info("\n-----------------------------------------------\n");
	se_info("%s", line);
	se_info("-----------------------------------------------\n");

#ifdef PSA_COMPLIANT
	if (memcmp(line, "TEST_GC_ACRYPTO_PSA", 19) != 0) {
		se_info("Skipping Test: Test Case is NOT PSA_COMPLIANT\n");
		goto out;
	}
#else
	if (memcmp(line, "TEST_GC_ACRYPTO_NON_PSA", 23) != 0) {
		se_info("Skipping Test: Test Case is PSA_COMPLIANT\n");
		goto out;
	}
#endif

	test_status = prepare_and_run_gc_acrypto_test(key_store_hdl, fp);

	if (test_status == TEST_STATUS_SUCCESS) {
		printf("%s: SUCCESS\n", test_id);
		++tgc_acrypto_passed;
		++(*tests_passed);
	} else if (test_status == TEST_STATUS_FAILED) {
		printf("%s: FAILED\n", test_id);
		++tgc_acrypto_failed;
		++(*tests_failed);
	} else if (test_status == TEST_STATUS_INVALID) {
		printf("%s: INVALID\n", test_id);
		++tgc_acrypto_invalids;
		++(*tests_invalid);
	} else if (test_status == TEST_STATUS_SKIPPED) {
		printf("%s: SKIPPED\n", test_id);
		--tgc_acrypto_total;
		--(*tests_total);
	}

out:
	if (test_id)
		free(test_id);

	se_info("\n------------------------------------------------------------------\n");
	se_info("TGC_ACRYPTO TESTS STATUS:: TOTAL: %u, SUCCESS: %u, FAILED: %u, INVALID: %u",
		tgc_acrypto_total, tgc_acrypto_passed, tgc_acrypto_failed,
		tgc_acrypto_invalids);
	se_info("\n------------------------------------------------------------------\n\n");
}
#endif
