// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <stdio.h>

#include "test_common.h"
#include "hsm_api.h"

#ifdef PSA_COMPLIANT
static uint8_t salt[32] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
};

static uint8_t fixed_info[16] = {
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
};

/* Key Derivation operation - Plaintext mode - HKDF */
static uint8_t test_key_derivation_subtest_01(uint32_t key_mgmt_hdl,
					      uint32_t key_store_id,
					      uint8_t *ikm,
					      uint32_t ikm_size,
					      uint8_t *okm,
					      uint32_t okm_size)
{
	hsm_err_t err;
	op_key_derivation_args_t args = {0};
	op_key_derivation_algo_hkdf_args_t hkdf_args = {0};

	printf("\nHKDF SHA256: ");

	/* Populate HKDF algorithm arguments */
	hkdf_args.vers = HSM_KEY_DERIVATION_ALGO_ARGS_HKDF_FORMAT_VERS;
	hkdf_args.ikm = ikm;
	hkdf_args.ikm_size = ikm_size;
	hkdf_args.salt = salt;
	hkdf_args.salt_size = sizeof(salt);
	hkdf_args.fixed_info = fixed_info;
	hkdf_args.fixed_info_size = sizeof(fixed_info);
	hkdf_args.okm = okm;
	hkdf_args.okm_size = okm_size;

	/* Key Derivation command arguments */
	args.algorithm = HSM_KEY_DERIVATION_HKDF_SHA256;
	args.flags = HSM_OP_KEY_DERIVATION_FLAGS_PLAINTEXT;
	args.key_derivation_algo_args = &hkdf_args;
	args.key_derivation_algo_args_size = sizeof(op_key_derivation_algo_hkdf_args_t);

	err = hsm_key_derivation(get_se_lib_serv_hdl(), &args);
	if (err != HSM_NO_ERROR) {
		printf("hsm_key_derivation (plaintext) err: 0x%x. --> FAILED\n",
		       err);
		return TEST_FAILED;
	}

	printf("hsm_key_derivation (plaintext) [key_id=0x%x] --> SUCCESS\n",
	       args.derived_key_id);

	printf("OKM:\n");
	dump_hex(hkdf_args.okm, hkdf_args.okm_size);

	return TEST_SUCCESS;
}

/* Key Derivation operation - Plaintext mode - HKDF Extract */
static uint8_t test_key_derivation_subtest_02(uint32_t key_mgmt_hdl,
					      uint32_t key_store_id,
					      uint8_t *ikm,
					      uint32_t ikm_size,
					      uint8_t *prk,
					      uint32_t prk_size)
{
	hsm_err_t err;
	op_key_derivation_args_t args = {0};
	op_key_derivation_algo_hkdf_args_t hkdf_extract_args = {0};

	printf("\nHKDF Extract SHA256: ");

	/* Populate HKDF (Extract) algorithm arguments */
	hkdf_extract_args.vers = HSM_KEY_DERIVATION_ALGO_ARGS_HKDF_FORMAT_VERS;
	hkdf_extract_args.ikm = ikm;
	hkdf_extract_args.ikm_size = ikm_size;
	hkdf_extract_args.salt = salt;
	hkdf_extract_args.salt_size = sizeof(salt);
	hkdf_extract_args.fixed_info = fixed_info;
	hkdf_extract_args.fixed_info_size = sizeof(fixed_info);
	hkdf_extract_args.okm = prk;
	hkdf_extract_args.okm_size = prk_size;

	/* Key Derivation command arguments */
	args.algorithm = HSM_KEY_DERIVATION_HKDF_EXTRACT_SHA256;
	args.flags = HSM_OP_KEY_DERIVATION_FLAGS_PLAINTEXT;
	args.key_derivation_algo_args = &hkdf_extract_args;
	args.key_derivation_algo_args_size = sizeof(op_key_derivation_algo_hkdf_args_t);

	err = hsm_key_derivation(get_se_lib_serv_hdl(), &args);
	if (err != HSM_NO_ERROR) {
		printf("hsm_key_derivation (plaintext) err: 0x%x. --> FAILED\n",
		       err);
		return TEST_FAILED;
	}

	printf("hsm_key_derivation (plaintext) [key_id=0x%x] --> SUCCESS\n",
	       args.derived_key_id);

	printf("PRK:\n");
	dump_hex(hkdf_extract_args.okm, hkdf_extract_args.okm_size);

	return TEST_SUCCESS;
}

/* Key Derivation operation - Plaintext mode - HKDF Expand */
static uint8_t test_key_derivation_subtest_03(uint32_t key_mgmt_hdl,
					      uint32_t key_store_id,
					      uint8_t *prk,
					      uint32_t prk_size,
					      uint8_t *okm,
					      uint32_t okm_size)
{
	hsm_err_t err;
	op_key_derivation_args_t args = {0};
	op_key_derivation_algo_hkdf_args_t hkdf_expand_args = {0};

	printf("\nHKDF Expand SHA256: ");

	/* Populate HKDF (Expand) algorithm arguments */
	hkdf_expand_args.vers = HSM_KEY_DERIVATION_ALGO_ARGS_HKDF_FORMAT_VERS;
	hkdf_expand_args.ikm = prk;
	hkdf_expand_args.ikm_size = prk_size;
	hkdf_expand_args.salt = salt;
	hkdf_expand_args.salt_size = sizeof(salt);
	hkdf_expand_args.fixed_info = fixed_info;
	hkdf_expand_args.fixed_info_size = sizeof(fixed_info);
	hkdf_expand_args.okm = okm;
	hkdf_expand_args.okm_size = okm_size;

	/* Key Derivation command arguments */
	args.algorithm = HSM_KEY_DERIVATION_HKDF_EXPAND_SHA256;
	args.flags = HSM_OP_KEY_DERIVATION_FLAGS_PLAINTEXT;
	args.key_derivation_algo_args = &hkdf_expand_args;
	args.key_derivation_algo_args_size = sizeof(op_key_derivation_algo_hkdf_args_t);

	err = hsm_key_derivation(get_se_lib_serv_hdl(), &args);
	if (err != HSM_NO_ERROR) {
		printf("hsm_key_derivation (plaintext) err: 0x%x. --> FAILED\n",
		       err);
		return TEST_FAILED;
	}

	printf("hsm_key_derivation (plaintext) [key_id=0x%x] --> SUCCESS\n",
	       args.derived_key_id);

	printf("OKM:\n");
	dump_hex(hkdf_expand_args.okm, hkdf_expand_args.okm_size);

	return TEST_SUCCESS;
}

uint8_t test_key_derivation(uint32_t key_mgmt_hdl, uint32_t key_store_id)
{
	uint8_t ret = TEST_SUCCESS;
	hsm_err_t err;
	uint8_t ikm[32] = {0};
	uint8_t prk[32] = {0};
	uint8_t hkdf_okm[32] = {0};
	uint8_t hkdf_expand_okm[32] = {0};
	uint32_t hkdf_okm_id = 0;

	printf("\n----------------------------------------------------------\n");
	printf("Key Derivation");
	printf("\n----------------------------------------------------------\n");

	/* Generate a key (IKM) plaintext for Key Derivation operations */
	err = generate_test_key(key_mgmt_hdl,
				HSM_KEY_TYPE_AES,
				HSM_KEY_SIZE_AES_256,
				0, 0, 0, 0,
				HSM_OP_KEY_GENERATION_FLAGS_PLAINTEXT_KEY,
				0,
				sizeof(ikm), ikm,
				0, NULL,
				NULL);
	if (err != HSM_NO_ERROR)
		return TEST_FAILED;

	ret |= test_key_derivation_subtest_01(key_mgmt_hdl, key_store_id,
					      ikm, sizeof(ikm),
					      hkdf_okm, sizeof(hkdf_okm));

	ret |= test_key_derivation_subtest_02(key_mgmt_hdl, key_store_id,
					      ikm, sizeof(ikm),
					      prk, sizeof(prk));

	ret |= test_key_derivation_subtest_03(key_mgmt_hdl, key_store_id,
					      prk, sizeof(prk),
					      hkdf_expand_okm, sizeof(hkdf_expand_okm));

	if (memcmp(hkdf_okm, hkdf_expand_okm, sizeof(hkdf_okm))) {
		printf("HKDF OKM outputs do not match. --> FAILED\n");
		return TEST_FAILED;
	}

	printf("\n----------------------------------------------------------\n");

	return ret;
}
#endif
