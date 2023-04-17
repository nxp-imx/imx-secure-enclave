// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <stdio.h>

#include "common.h"
#include "hsm_api.h"
#include "test_utils_tv.h"

static void sign_verify_test(hsm_hdl_t key_store_hdl,
						uint32_t key_identifier,
						uint32_t message_size,
						uint8_t *message,
						uint16_t signature_size,
						hsm_signature_scheme_id_t scheme_id,
						hsm_op_generate_sign_flags_t sign_gen_flags,
						hsm_op_verify_sign_flags_t sign_verify_flags,
						hsm_pubkey_type_t pkey_type,
						uint16_t key_size,
						hsm_bit_key_sz_t bit_key_sz,
						uint16_t exp_signature_size,
						hsm_verification_status_t exp_verification_status,
						uint32_t exp_sign_gen_rsp,
						uint32_t exp_sign_verify_rsp,
						int8_t *test_status)
{
	op_generate_sign_args_t sig_gen_args = {0};
	op_verify_sign_args_t sig_ver_args = {0};
	hsm_verification_status_t verification_status;
	hsm_err_t hsmret1 = HSM_GENERAL_ERROR;
	hsm_err_t hsmret2 = HSM_GENERAL_ERROR;
	uint8_t *signature = NULL;
	op_pub_key_recovery_args_t pkey_recv_args = {0};
	uint8_t *loc_pub_key = NULL;
	hsm_hdl_t hsm_session_hdl = get_hsm_session_hdl();
	*test_status = 0;

	signature = (uint8_t *) malloc(signature_size*sizeof(uint8_t));

	if (signature == NULL) {
		printf("\nError: Couldn't allocate memory for Signature\n");
		goto out;
	}

	loc_pub_key = (uint8_t *) malloc(key_size*sizeof(uint8_t));

	if (loc_pub_key == NULL) {
		printf("\nError: Couldn't allocate memory for Key\n");
		goto out;
	}

	memset(signature, 0, sizeof(signature));
	memset(loc_pub_key, 0, sizeof(loc_pub_key));

	/* Signature Generation */
	sig_gen_args.key_identifier = key_identifier;
	sig_gen_args.message_size = message_size;
	sig_gen_args.message = message;
	sig_gen_args.signature_size = signature_size;
	sig_gen_args.signature = signature;
	sig_gen_args.scheme_id = scheme_id;
	sig_gen_args.flags = sign_gen_flags;

	hsmret1 = hsm_do_sign(key_store_hdl, &sig_gen_args);
	printf("\nhsm_do_sign ret:0x%x\n", hsmret1);

	if (hsmret1 != exp_sign_gen_rsp) {
		printf("\nEXP_SIGN_GEN_RSP didn't match Signature Generation Resp(0x%x)\n",
				hsmret1);
		goto out;
	}

#ifdef PSA_COMPLIANT
	/*
	 * The Expected Signature size value in HSM API Signature Generation op
	 * args, is only valid for cases HSM_NO_ERROR, HSM_OUT_TOO_SMALL,
	 * HSM_GENERAL_ERROR.
	 */

	if (hsmret1 == HSM_NO_ERROR || hsmret1 == HSM_OUT_TOO_SMALL ||
		hsmret1 == HSM_GENERAL_ERROR) {

		if (sig_gen_args.exp_signature_size != exp_signature_size) {
			printf("\nEXP_SIGNATURE_SIZE didn't match API Resp Signature size(%u)\n",
					sig_gen_args.exp_signature_size);
			goto out;
		}
	}
#endif

	/* Public Key Exportation/Recovery*/
	pkey_recv_args.key_identifier = key_identifier;
	pkey_recv_args.out_key      = loc_pub_key;
	pkey_recv_args.out_key_size = key_size;

	hsmret2 = hsm_pub_key_recovery(key_store_hdl, &pkey_recv_args);
	printf("\nhsm_pub_key_recovery ret:0x%x\n", hsmret2);

	/* Signature Verification */
	sig_ver_args.key = loc_pub_key;
	sig_ver_args.key_size = key_size;
#ifdef PSA_COMPLIANT
	sig_ver_args.key_sz = bit_key_sz;
	sig_ver_args.pkey_type = pkey_type;
#endif
	sig_ver_args.message_size = message_size;
	sig_ver_args.message = message;
	sig_ver_args.signature_size = signature_size;
	sig_ver_args.signature = signature;
	sig_ver_args.scheme_id = scheme_id;
	sig_ver_args.flags = sign_verify_flags;

	hsmret2 = hsm_verify_sign(hsm_session_hdl, &sig_ver_args, &verification_status);
	printf("\nhsm_verify_signature ret:0x%x\n", hsmret2);

	if (hsmret2 != exp_sign_verify_rsp) {
		printf("\nEXP_SIGN_VERIFY_RSP didn't match Signature Verification Resp(0x%x)\n",
				hsmret2);
		goto out;
	}

	if (sig_ver_args.verification_status != exp_verification_status) {
		printf("\nEXP_VERIFICATION_STATUS didn't match Actual status(0x%x)\n",
			sig_ver_args.verification_status);
		goto out;
	}

	*test_status = 1;

out:
	if (signature)
		free(signature);

	if (loc_pub_key)
		free(loc_pub_key);
}

static int8_t prepare_and_run_sign_verify_test(hsm_hdl_t key_store_hdl, FILE *fp)
{
	hsm_err_t ret = HSM_GENERAL_ERROR;

	uint8_t req_params_n = 14;
	uint8_t input_ctr = 0;
	uint8_t invalid_read = 0;
	uint8_t call_sign_verify_test = -1;
	int8_t test_status = 0; /* 0 -> FAILED, 1 -> PASSED, -1 -> INVALID*/
	size_t len = 0;
	ssize_t read = 0;

	char *param_name = NULL;
	char *param_value_token = NULL;
	char *temp = NULL;
	char *line = NULL;

	uint32_t key_tv_id = 0;
	/* Signature Generation */
	uint32_t key_identifier = 0;
	uint32_t message_size = 0;
	uint8_t *message = NULL;
	uint16_t signature_size = 0;
	hsm_signature_scheme_id_t scheme_id;
	hsm_op_generate_sign_flags_t sign_gen_flags;
	uint32_t exp_sign_gen_rsp = 0;
	uint16_t exp_signature_size = 0;
	/* Signature Verification */
	hsm_op_verify_sign_flags_t sign_verify_flags;
	hsm_pubkey_type_t pkey_type;
	uint16_t key_size = 0;
	hsm_bit_key_sz_t bit_key_sz;
	uint32_t exp_sign_verify_rsp = 0;
	hsm_verification_status_t exp_verification_status;

	while ((read = getline(&line, &len, fp)) != -1) {

		if (memcmp(line, "TEST_SIGN_VERIFY_END", 20) == 0) {

			if (input_ctr == req_params_n) {
				call_sign_verify_test = 1;
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

		if (strcmp(param_name, "KEY_TV_ID") == 0) {

			key_tv_id = (uint32_t)parse_param_value(param_value_token,
							param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "MESSAGE_SIZE") == 0) {

			message_size = (uint32_t)parse_param_value(param_value_token,
						param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "MESSAGE") == 0) {

			message = (uint8_t *) malloc(message_size * sizeof(uint8_t));

			if (message == NULL) {
				invalid_read = 1;
				printf("\nError: Couldn't allocate memory for %s\n", param_name);
				break;
			}

			parse_param_value_buffer(fp, &message, message_size, param_name,
									&input_ctr, &invalid_read);

		} else if (strcmp(param_name, "SIGNATURE_SIZE") == 0) {

			signature_size = (uint16_t)parse_param_value(param_value_token,
							param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "SCHEME_ID") == 0) {

			scheme_id = (hsm_signature_scheme_id_t)parse_param_value(param_value_token,
							param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "SIGN_GEN_FLAGS") == 0) {

			sign_gen_flags = (hsm_op_generate_sign_flags_t)parse_param_value(
								param_value_token, param_name,
								&input_ctr, &invalid_read);

		} else if (strcmp(param_name, "SIGN_VERIFY_FLAGS") == 0) {

			sign_verify_flags = (hsm_op_verify_sign_flags_t)parse_param_value(
								param_value_token, param_name,
								&input_ctr, &invalid_read);

		} else if (strcmp(param_name, "PKEY_TYPE") == 0) {

			pkey_type = (hsm_pubkey_type_t)parse_param_value(param_value_token,
							param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "KEY_SIZE") == 0) {

			key_size = (uint16_t)parse_param_value(param_value_token,
							param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "BIT_KEY_SZ") == 0) {

			bit_key_sz = (hsm_bit_key_sz_t)parse_param_value(param_value_token,
							param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "EXP_SIGNATURE_SIZE") == 0) {

			exp_signature_size = (uint16_t)parse_param_value(param_value_token,
							param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "EXP_VERIFICATION_STATUS") == 0) {

			exp_verification_status = (hsm_verification_status_t)parse_param_value(
							param_value_token, param_name,
							&input_ctr, &invalid_read);

		} else if (strcmp(param_name, "EXP_SIGN_GEN_RSP") == 0) {

			exp_sign_gen_rsp = (uint32_t)parse_param_value(param_value_token,
							param_name, &input_ctr, &invalid_read);

		} else if (strcmp(param_name, "EXP_SIGN_VERIFY_RSP") == 0) {

			exp_sign_verify_rsp = (uint32_t)parse_param_value(param_value_token,
							param_name, &input_ctr, &invalid_read);
		}

		/* Invalid value for any param. */
		if (invalid_read == 1)
			break;
	}

	if (call_sign_verify_test == 1) {

		printf("Key TV ID         : %u\n", key_tv_id);
		printf("Message Size      : %u\n", message_size);
		printf("\nMessage           :\n");
		print_buffer(message, message_size);
		printf("Signature Size    : %u\n", signature_size);
		printf("Scheme ID         : 0x%x\n", scheme_id);
		printf("Flags (SIGN_GEN_FLAGS)     : 0x%x\n", sign_gen_flags);
		printf("Flags (SIGN_VERIFY_FLAGS)  : 0x%x\n", sign_verify_flags);
		printf("Public Key Type   : 0x%x\n", pkey_type);
		printf("Key Size          : %u\n", key_size);
		printf("Bit Key Size      : %u\n", bit_key_sz);
		printf("Expected Signature Size   : %u\n", exp_signature_size);
		printf("Expected Verification Status  : 0x%x\n", exp_verification_status);
		printf("Expected Sign Generation Resp   : 0x%x\n", exp_sign_gen_rsp);
		printf("Expected Sign Verification Resp : 0x%x\n", exp_sign_verify_rsp);

		printf("----------------------------------------------------\n");

		key_identifier = get_test_key_identifier(key_tv_id);

		sign_verify_test(key_store_hdl, key_identifier, message_size,
					message, signature_size, scheme_id, sign_gen_flags,
					sign_verify_flags, pkey_type, key_size, bit_key_sz,
					exp_signature_size, exp_verification_status,
					exp_sign_gen_rsp, exp_sign_verify_rsp, &test_status);
	}

	if (invalid_read == 1 || read == -1) {
		test_status = -1;

		/* EOF encountered before reading all param values. */
		if (read == -1)
			printf("\nEOF reached. TEST_SIGN_VERIFY_END not detected.\n");

		printf("\nSkipping this Test Case\n");
	}

	if (message)
		free(message);

	if (line)
		free(line);

	return test_status;
}

void sign_verify_test_tv(hsm_hdl_t key_store_hdl, FILE *fp, char *line)
{
	int8_t test_status = 0;
	static uint8_t tsign_verify_passed;
	static uint8_t tsign_verify_failed;
	static uint8_t tsign_verify_invalids;
	static uint8_t tsign_verify_total;

	++tsign_verify_total;

	printf("\n-----------------------------------------------\n");
	printf("%s", line);
	printf("-----------------------------------------------\n");

#ifdef PSA_COMPLIANT
	if (memcmp(line, "TEST_SIGN_VERIFY_PSA", 20) != 0) {
		printf("Skipping Test: Test Case is NOT PSA_COMPLIANT\n");
		goto out;
	}
#else
	if (memcmp(line, "TEST_SIGN_VERIFY_NON_PSA", 24) != 0) {
		printf("Skipping Test: Test Case is PSA_COMPLIANT\n");
		goto out;
	}
#endif
	test_status = prepare_and_run_sign_verify_test(key_store_hdl, fp);

	if (test_status == 1) {
		printf("\nTEST RESULT: SUCCESS\n");
		++tsign_verify_passed;
	} else if (test_status == 0) {
		printf("\nTEST RESULT: FAILED\n");
		++tsign_verify_failed;
	} else if (test_status == -1) {
		printf("\nTEST RESULT: INVALID\n");
		++tsign_verify_invalids;
	}

out:

	printf("\n------------------------------------------------------------------\n");
	printf("TSIGN_VERIFY TESTS STATUS:: TOTAL: %u, SUCCESS: %u, FAILED: %u, INVALID: %u",
		tsign_verify_total, tsign_verify_passed, tsign_verify_failed,
		tsign_verify_invalids);
	printf("\n------------------------------------------------------------------\n\n");

}

