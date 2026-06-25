// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2026 NXP
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "test_common.h"
#include "hsm_api.h"

#define TEST_ED25519_PUBKEY_SIZE 32
#define TEST_ED448_PUBKEY_SIZE   57
#define TEST_ED25519_SIGNATURE_SIZE 64
#define TEST_ED448_SIGNATURE_SIZE   114

static uint8_t payload[32] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};

static uint8_t ecc_nist_256_priv_key[32]  = {
	0x14, 0x76, 0x5e, 0x2b, 0xc8, 0xa6, 0x68, 0xe6,
	0x38, 0x35, 0x3e, 0x0b, 0x52, 0x60, 0xa4, 0xc9,
	0x29, 0x2d, 0xb5, 0x96, 0xb7, 0xba, 0x00, 0x10,
	0x1d, 0x06, 0x6f, 0x14, 0x41, 0xa4, 0x7c, 0x61,
};

static uint8_t ecc_nist_256_pub_key[64]  = {
	0x12, 0x28, 0x97, 0x18, 0xb5, 0x67, 0x96, 0x75,
	0xe0, 0x98, 0x08, 0x48, 0x12, 0x11, 0x0b, 0xba,
	0xce, 0x06, 0x66, 0x57, 0x28, 0xfe, 0xf3, 0xe1,
	0x9d, 0x1a, 0x45, 0x03, 0xea, 0xc6, 0xab, 0x55,
	0x42, 0x7f, 0xfa, 0xa1, 0xcb, 0x37, 0xd1, 0xc9,
	0xbf, 0xd2, 0xa1, 0x2b, 0xf2, 0x69, 0x24, 0xc2,
	0x6d, 0xe3, 0xe4, 0x33, 0x4f, 0xbf, 0xa8, 0x16,
	0x10, 0x92, 0xaa, 0xb6, 0xbf, 0xd1, 0xae, 0xe0,
};

static uint8_t sm2_id[16] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
};

hsm_err_t hsm_sign_verify_tests(hsm_hdl_t sess_hdl, hsm_hdl_t key_store_hdl,
				uint32_t key_id,
				hsm_signature_scheme_id_t scheme_id,
#ifdef PSA_COMPLIANT
				uint16_t key_type,
				hsm_pubkey_type_t pkey_type, hsm_bit_key_sz_t key_sz,
				uint8_t *sm2_id, uint16_t sm2_id_size,
#endif
				uint8_t *signature_data, uint32_t sign_data_sz,
				uint8_t *input_data, uint32_t input_data_sz,
#ifdef PSA_COMPLIANT
				uint8_t *priv_key, uint16_t priv_key_size,
#endif
				uint8_t *pub_key, uint32_t pub_key_sz,
				uint8_t input_data_type)
{
	op_generate_sign_args_t sig_gen_args = {0};
	op_verify_sign_args_t sig_ver_args = {0};
	hsm_verification_status_t verif_status = 0;
	hsm_err_t hsmret;

	if (input_data_type == TEST_INPUT_DIGEST) {
		sig_gen_args.flags = HSM_OP_GENERATE_SIGN_FLAGS_INPUT_DIGEST;
		sig_ver_args.flags = HSM_OP_VERIFY_SIGN_FLAGS_INPUT_DIGEST;
	} else {
		sig_gen_args.flags = HSM_OP_GENERATE_SIGN_FLAGS_INPUT_MESSAGE;
		sig_ver_args.flags = HSM_OP_VERIFY_SIGN_FLAGS_INPUT_MESSAGE;
	}

#ifdef PSA_COMPLIANT
	if (!key_id) {
		sig_gen_args.flags |= HSM_OP_GENERATE_SIGN_FLAGS_PLAINTEXT_KEY;
		sig_gen_args.key_type = key_type;
		sig_gen_args.key_security_size = key_sz;
		sig_gen_args.priv_key_size = priv_key_size;
		sig_gen_args.priv_key = priv_key;
	}
#endif
	sig_gen_args.key_identifier = key_id;
	sig_gen_args.scheme_id = scheme_id;
	sig_gen_args.message = input_data;
	sig_gen_args.signature = signature_data;
	sig_gen_args.message_size = input_data_sz;
	sig_gen_args.signature_size = sign_data_sz;
#ifdef PSA_COMPLIANT
	sig_gen_args.salt_len = 0;
	sig_gen_args.sm2_pub_key_size = pub_key_sz;
	sig_gen_args.sm2_pub_key = pub_key;
	sig_gen_args.sm2_id_size = sm2_id_size;
	sig_gen_args.sm2_id = sm2_id;
#else
	sig_gen_args.svc_flags = 0;
#endif
	hsmret = hsm_do_sign(key_store_hdl, &sig_gen_args);
	if (hsmret)
		printf("hsm_do_sign failed ret:0x%x\n", hsmret);

	/* Signature Verification using Plaintext key */
	sig_ver_args.key = pub_key;
	sig_ver_args.message = input_data;
	sig_ver_args.signature = signature_data;
	sig_ver_args.key_size = pub_key_sz;
	sig_ver_args.signature_size = sign_data_sz;
	sig_ver_args.message_size = input_data_sz;
	sig_ver_args.scheme_id = scheme_id;
#ifdef PSA_COMPLIANT
	sig_ver_args.pkey_type = pkey_type;
	sig_ver_args.key_sz   = key_sz;
	sig_ver_args.salt_len = 0;
	sig_ver_args.sm2_id_size = sm2_id_size;
	sig_ver_args.sm2_id = sm2_id;
#endif
	hsmret = hsm_verify_sign(sess_hdl, &sig_ver_args, &verif_status);
	if (hsmret)
		printf("hsm_verify_signature ret:0x%x\n", hsmret);

	if (verif_status != HSM_VERIFICATION_STATUS_SUCCESS)
		printf("Verification FAIL, status:0x%x\n", verif_status);

#ifdef PSA_COMPLIANT
	/* Signature Verification using Opaque key */
	if (key_id &&
	    ((se_get_soc_id() == SOC_IMX95 && se_get_soc_rev() >= SOC_REV_B0) ||
	     (se_get_soc_id() & SOC_MASK_IMX94) == SOC_IMX94 ||
	     se_get_soc_id() == SOC_IMX937 ||
	      se_get_soc_id() == SOC_IMX952)) {
		sig_ver_args.flags |= HSM_OP_VERIFY_SIGN_FLAGS_OPAQUE_KEY;
		sig_ver_args.key_identifier = key_id;
		sig_ver_args.key = NULL;
		sig_ver_args.pkey_type = 0;
		sig_ver_args.key_size = 0;
		sig_ver_args.key_sz   = 0;

		hsmret = hsm_verify_sign(key_store_hdl, &sig_ver_args, &verif_status);

		if (hsmret)
			printf("hsm_verify_signature (opaque key) ret:0x%x\n", hsmret);

		if (verif_status != HSM_VERIFICATION_STATUS_SUCCESS)
			printf("Verification FAIL, status:0x%x\n", verif_status);
	}
#endif
	return hsmret;
}

#ifdef PSA_COMPLIANT
hsm_err_t hsm_sign_verify_plaintext_tests(hsm_hdl_t sess_hdl,
					  hsm_hdl_t key_store_hdl,
					  hsm_hdl_t key_mgmt_hdl)
{
	hsm_err_t ret;
	uint8_t signature_data[512] = {0};

	printf("----------------------------------------------------------------\n");
	printf("Secondary API Test: HSM_DO_SIGN then HSM_VERIFY_SIGN (Plaintext)\n");
	printf("----------------------------------------------------------------\n");

	ret = hsm_sign_verify_tests(sess_hdl, key_store_hdl,
				    0,
				    HSM_SIGNATURE_SCHEME_ECDSA_SHA256,
				    HSM_KEY_TYPE_ECC_NIST,
				    HSM_PUBKEY_TYPE_ECC_NIST,
				    HSM_KEY_SIZE_ECC_NIST_256,
				    NULL, 0,
				    signature_data,
				    2 * BITS_TO_BYTES(HSM_KEY_SIZE_ECC_NIST_256),
				    payload,
				    sizeof(payload),
				    ecc_nist_256_priv_key,
				    sizeof(ecc_nist_256_priv_key),
				    ecc_nist_256_pub_key,
				    sizeof(ecc_nist_256_pub_key),
				    TEST_INPUT_DIGEST);

	printf("HSM_KEY_SIZE_ECC_NIST_256 & HSM_SIGNATURE_SCHEME_ECDSA_SHA256\n");
	if (ret != HSM_NO_ERROR)
		printf("Result ---> FAILED\n");
	else
		printf("Result ---> SUCCESS\n");

	printf("----------------------------------------------------------------\n");
	return ret;
}

static hsm_err_t hsm_sign_verify_eddsa_tests_helper(hsm_hdl_t sess_hdl,
						    hsm_hdl_t key_store_hdl,
						    hsm_hdl_t key_mgmt_hdl,
						    hsm_bit_key_sz_t bit_key_size,
						    hsm_permitted_algo_t permitted_algo,
						    hsm_signature_scheme_id_t algo)
{
	hsm_err_t ret;
	uint32_t key_id = 0;
	uint8_t pub_key[64] = {0};
	uint8_t pub_key_size = 0;
	uint8_t signature[128] = {0};
	uint8_t signature_size = 0;
	uint8_t test_status = TEST_STATUS_FAILED;

	if (bit_key_size == HSM_KEY_SIZE_ECC_TWISTED_EDWARDS_255) {
		pub_key_size = TEST_ED25519_PUBKEY_SIZE;
		signature_size = TEST_ED25519_SIGNATURE_SIZE;
	} else if (bit_key_size == HSM_KEY_SIZE_ECC_TWISTED_EDWARDS_448) {
		pub_key_size = TEST_ED448_PUBKEY_SIZE;
		signature_size = TEST_ED448_SIGNATURE_SIZE;
	}

	// Generate key for the operation
	ret = generate_test_key(key_mgmt_hdl,
				HSM_KEY_TYPE_ECC_TWISTED_EDWARDS,
				bit_key_size,
				HSM_SE_KEY_STORAGE_VOLATILE,
				HSM_KEY_USAGE_SIGN_MSG | HSM_KEY_USAGE_VERIFY_MSG,
				permitted_algo,
				0,
				0,
				50,
				0, NULL,
				pub_key_size,
				pub_key,
				&key_id);
	if (ret != HSM_NO_ERROR)
		goto out;

	// Signature Generation and Signature Verification test
	ret = hsm_sign_verify_tests(sess_hdl, key_store_hdl, key_id,
				    algo,
				    0,
				    HSM_PUBKEY_TYPE_ECC_TWISTED_EDWARDS,
				    bit_key_size,
				    NULL, 0,
				    signature, signature_size,
				    payload, sizeof(payload),
				    0, 0,
				    pub_key, pub_key_size,
				    TEST_INPUT_MESSAGE);
	if (ret != HSM_NO_ERROR)
		goto out;

	test_status = TEST_STATUS_SUCCESS;

out:
	// Delete the test key
	if (key_id)
		delete_test_key(key_mgmt_hdl, key_id, 0);

	if (test_status == TEST_STATUS_SUCCESS)
		printf("\nResult ---> SUCCESS\n");
	else
		printf("\nResult ---> FAILURE\n");

	return ret;
}

void hsm_sign_verify_eddsa_tests(hsm_hdl_t sess_hdl,
				 hsm_hdl_t key_store_hdl,
				 hsm_hdl_t key_mgmt_hdl)
{
	printf("HSM_KEY_SIZE_ECC_TWISTED_EDWARDS_255 & HSM_SIGNATURE_SCHEME_ED25519PH:");
	hsm_sign_verify_eddsa_tests_helper(sess_hdl, key_store_hdl, key_mgmt_hdl,
					   HSM_KEY_SIZE_ECC_TWISTED_EDWARDS_255,
					   PERMITTED_ALGO_ED25519PH,
					   HSM_SIGNATURE_SCHEME_ED25519PH);

	printf("HSM_KEY_SIZE_ECC_TWISTED_EDWARDS_255 & HSM_SIGNATURE_SCHEME_PURE_EDDSA:");
	hsm_sign_verify_eddsa_tests_helper(sess_hdl, key_store_hdl, key_mgmt_hdl,
					   HSM_KEY_SIZE_ECC_TWISTED_EDWARDS_255,
					   PERMITTED_ALGO_PURE_EDDSA,
					   HSM_SIGNATURE_SCHEME_PURE_EDDSA);

	printf("HSM_KEY_SIZE_ECC_TWISTED_EDWARDS_255 & ED25519PH (EDDSA_ALL):");
	hsm_sign_verify_eddsa_tests_helper(sess_hdl, key_store_hdl, key_mgmt_hdl,
					   HSM_KEY_SIZE_ECC_TWISTED_EDWARDS_255,
					   PERMITTED_ALGO_EDDSA_ALL,
					   HSM_SIGNATURE_SCHEME_ED25519PH);

	printf("HSM_KEY_SIZE_ECC_TWISTED_EDWARDS_255 & PURE_EDDSA (EDDSA_ALL):");
	hsm_sign_verify_eddsa_tests_helper(sess_hdl, key_store_hdl, key_mgmt_hdl,
					   HSM_KEY_SIZE_ECC_TWISTED_EDWARDS_255,
					   PERMITTED_ALGO_EDDSA_ALL,
					   HSM_SIGNATURE_SCHEME_PURE_EDDSA);

	printf("HSM_KEY_SIZE_ECC_TWISTED_EDWARDS_448 & HSM_SIGNATURE_SCHEME_ED448PH:");
	hsm_sign_verify_eddsa_tests_helper(sess_hdl, key_store_hdl, key_mgmt_hdl,
					   HSM_KEY_SIZE_ECC_TWISTED_EDWARDS_448,
					   PERMITTED_ALGO_ED448PH,
					   HSM_SIGNATURE_SCHEME_ED448PH);

	printf("HSM_KEY_SIZE_ECC_TWISTED_EDWARDS_448 & HSM_SIGNATURE_SCHEME_PURE_EDDSA:");
	hsm_sign_verify_eddsa_tests_helper(sess_hdl, key_store_hdl, key_mgmt_hdl,
					   HSM_KEY_SIZE_ECC_TWISTED_EDWARDS_448,
					   PERMITTED_ALGO_PURE_EDDSA,
					   HSM_SIGNATURE_SCHEME_PURE_EDDSA);

	printf("HSM_KEY_SIZE_ECC_TWISTED_EDWARDS_448 & ED448PH (EDDSA_ALL):");
	hsm_sign_verify_eddsa_tests_helper(sess_hdl, key_store_hdl, key_mgmt_hdl,
					   HSM_KEY_SIZE_ECC_TWISTED_EDWARDS_448,
					   PERMITTED_ALGO_EDDSA_ALL,
					   HSM_SIGNATURE_SCHEME_ED448PH);

	printf("HSM_KEY_SIZE_ECC_TWISTED_EDWARDS_448 & PURE_EDDSA (EDDSA_ALL):");
	hsm_sign_verify_eddsa_tests_helper(sess_hdl, key_store_hdl, key_mgmt_hdl,
					   HSM_KEY_SIZE_ECC_TWISTED_EDWARDS_448,
					   PERMITTED_ALGO_EDDSA_ALL,
					   HSM_SIGNATURE_SCHEME_PURE_EDDSA);
}

/* SM2: Signature Generation & Verification using Opaque Key */
static uint8_t hsm_sign_verify_sm2_subtest_01(hsm_hdl_t sess_hdl,
					      hsm_hdl_t key_store_hdl,
					      hsm_hdl_t key_mgmt_hdl)
{
	uint8_t ret = TEST_FAILED;
	hsm_err_t err;
	uint32_t key_id = 0;
	uint16_t pub_key_size = 2 * BITS_TO_BYTES(HSM_KEY_SIZE_SM2_256);
	uint8_t pub_key[64] = {0};
	uint8_t signature[64] = {0};
	uint16_t signature_size = sizeof(signature);

	printf("HSM_KEY_SIZE_SM2_256 & HSM_SIGNATURE_SCHEME_SM2_SM3:");

	/* Generate SM2 key-pair */
	err = generate_test_key(key_mgmt_hdl,
				HSM_KEY_TYPE_SM2,
				HSM_KEY_SIZE_SM2_256,
				HSM_SE_KEY_STORAGE_VOLATILE,
				HSM_KEY_USAGE_SIGN_MSG | HSM_KEY_USAGE_VERIFY_MSG,
				HSM_SIGNATURE_SCHEME_SM2_SM3,
				0,
				0,
				50,
				0, NULL,
				pub_key_size,
				pub_key,
				&key_id);
	if (err != HSM_NO_ERROR)
		goto out;

	/* Signature Generation and Signature Verification using Opaque Key ID */
	err = hsm_sign_verify_tests(sess_hdl, key_store_hdl, key_id,
				    HSM_SIGNATURE_SCHEME_SM2_SM3,
				    0,
				    HSM_PUBKEY_TYPE_SM2,
				    HSM_KEY_SIZE_SM2_256,
				    sm2_id, sizeof(sm2_id),
				    signature, signature_size,
				    payload, sizeof(payload),
				    NULL, 0,
				    pub_key, pub_key_size,
				    TEST_INPUT_MESSAGE);
	if (err != HSM_NO_ERROR)
		goto out;

	ret = TEST_SUCCESS;

out:
	if (key_id) {
		err = delete_test_key(key_mgmt_hdl, key_id, 0);
		if (err != HSM_NO_ERROR)
			ret = TEST_FAILED;
	}

	if (ret == TEST_SUCCESS)
		printf("\nResult ---> SUCCESS\n");
	else
		printf("\nResult ---> FAILED\n");

	return ret;
}

/* SM2: Signature Generation & Verification using Plaintext Key */
static uint8_t hsm_sign_verify_sm2_subtest_02(hsm_hdl_t sess_hdl,
					      hsm_hdl_t key_store_hdl,
					      hsm_hdl_t key_mgmt_hdl)
{
	uint8_t ret = TEST_FAILED;
	hsm_err_t err;
	uint16_t pub_key_size = 2 * BITS_TO_BYTES(HSM_KEY_SIZE_SM2_256);
	uint8_t pub_key[64] = {0};
	uint16_t priv_key_size = BITS_TO_BYTES(HSM_KEY_SIZE_SM2_256);
	uint8_t priv_key[32] = {0};
	uint8_t signature[64] = {0};
	uint16_t signature_size = sizeof(signature);

	printf("HSM_KEY_SIZE_SM2_256 & HSM_SIGNATURE_SCHEME_SM2_SM3 (plainkey):");

	/* Generate SM2 key-pair plain key */
	err = generate_test_key(key_mgmt_hdl,
				HSM_KEY_TYPE_SM2, HSM_KEY_SIZE_SM2_256,
				0, 0, 0, 0,
				HSM_OP_KEY_GENERATION_FLAGS_PLAINTEXT_KEY,
				0,
				priv_key_size, priv_key,
				pub_key_size, pub_key,
				NULL);
	if (err != HSM_NO_ERROR)
		goto out;

	/* Signature Generation and Signature Verification using plain key */
	err = hsm_sign_verify_tests(sess_hdl, key_store_hdl, 0,
				    HSM_SIGNATURE_SCHEME_SM2_SM3,
				    HSM_KEY_TYPE_SM2,
				    HSM_PUBKEY_TYPE_SM2,
				    HSM_KEY_SIZE_SM2_256,
				    sm2_id, sizeof(sm2_id),
				    signature, signature_size,
				    payload, sizeof(payload),
				    priv_key, priv_key_size,
				    pub_key, pub_key_size,
				    TEST_INPUT_MESSAGE);
	if (err != HSM_NO_ERROR)
		goto out;

	ret = TEST_SUCCESS;

out:
	if (ret == TEST_SUCCESS)
		printf("\nResult ---> SUCCESS\n");
	else
		printf("\nResult ---> FAILED\n");
}

uint8_t hsm_sign_verify_sm2_tests(hsm_hdl_t sess_hdl, hsm_hdl_t key_store_hdl,
				  hsm_hdl_t key_mgmt_hdl)
{
	uint8_t ret = TEST_SUCCESS;

	ret |= hsm_sign_verify_sm2_subtest_01(sess_hdl, key_store_hdl, key_mgmt_hdl);
	ret |= hsm_sign_verify_sm2_subtest_02(sess_hdl, key_store_hdl, key_mgmt_hdl);

	return ret;
}
#endif
