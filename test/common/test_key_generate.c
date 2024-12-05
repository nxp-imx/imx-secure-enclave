// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#include "test_common.h"

#ifdef PSA_COMPLIANT
static hsm_err_t test_kgen_helper_plaintext(hsm_hdl_t key_mgmt_hdl,
					    hsm_key_type_t key_type,
					    hsm_bit_key_sz_t bit_key_sz,
					    uint16_t pub_key_sz,
					    uint16_t priv_key_sz)
{
	hsm_err_t ret;
	op_generate_key_args_t args = {0};
	uint8_t priv_key[512] = {0};
	uint8_t pub_key[1024] = {0};

	args.flags = HSM_OP_KEY_GENERATION_FLAGS_PLAINTEXT_KEY;
	args.key_type = key_type;
	args.bit_key_sz = bit_key_sz;
	args.out_size = pub_key_sz;
	args.out_key = pub_key;
	args.priv_out_key_sz = priv_key_sz;
	args.priv_out_key = priv_key;

	ret = hsm_generate_key(key_mgmt_hdl, &args);
	if (ret != HSM_NO_ERROR)
		printf("hsm_generate_key ret: 0x%x. failed.\n", ret);

	return ret;
}

hsm_err_t test_generate_key(hsm_hdl_t key_mgmt_hdl)
{
	hsm_err_t ret;

	printf("\n--------------------------------------\n");
	printf("Generate Key API test - Plaintext key");
	printf("\n--------------------------------------\n");

	ret = test_kgen_helper_plaintext(key_mgmt_hdl,
					 HSM_KEY_TYPE_AES,
					 HSM_KEY_SIZE_AES_256,
					 0,
					 BITS_TO_BYTES(HSM_KEY_SIZE_AES_256));
	printf("Test Output for HSM_KEY_SIZE_AES_256:\n");
	if (ret != HSM_NO_ERROR)
		printf("Result --> FAILED");
	else
		printf("Result --> SUCCESS");

	ret = test_kgen_helper_plaintext(key_mgmt_hdl,
					 HSM_KEY_TYPE_ECC_NIST,
					 HSM_KEY_SIZE_ECC_NIST_256,
					 2 * BITS_TO_BYTES(HSM_KEY_SIZE_ECC_NIST_256),
					 BITS_TO_BYTES(HSM_KEY_SIZE_ECC_NIST_256));
	printf("\nTest Output for HSM_KEY_SIZE_ECC_NIST_256:\n");
	if (ret != HSM_NO_ERROR)
		printf("Result --> FAILED");
	else
		printf("Result --> SUCCESS");

	printf("\n--------------------------------------\n");
	return ret;
}
#endif
