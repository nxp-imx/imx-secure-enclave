// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "common.h"

#define AUTH_CHALLENGE_SIZE 16u
#define CERTIFICATE_SIZE 0xAFu

static uint8_t auth_challenge[AUTH_CHALLENGE_SIZE] = {
	0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
	0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
};

static uint8_t certificate[CERTIFICATE_SIZE];

#ifdef PSA_COMPLIANT
void pub_key_attest_test(hsm_hdl_t key_store_hdl, hsm_hdl_t key_mgmt_hdl)
{
	hsm_err_t err;
	op_generate_key_args_t key_gen_args;
	op_pub_key_attest_args_t pub_key_attest_args;
	uint32_t key_id = 0;
	uint32_t key_attestation_id = 0;

	memset(&key_gen_args, 0, sizeof(key_gen_args));
	memset(&pub_key_attest_args, 0, sizeof(pub_key_attest_args));
	memset(certificate, 0, sizeof(certificate));

	printf("\n------------------------------------------------\n");
	printf("Public Key Attestation API Test:");
	printf("\n------------------------------------------------\n");

	//Generate the Key to be attested, Key ID #1
	key_gen_args.key_identifier = &key_id;
	key_gen_args.key_lifecycle = 0;
	key_gen_args.key_group = 32;
	key_gen_args.key_lifetime = HSM_SE_KEY_STORAGE_VOLATILE;
	key_gen_args.key_usage = HSM_KEY_USAGE_SIGN_HASH |
				 HSM_KEY_USAGE_VERIFY_HASH;
	key_gen_args.permitted_algo = PERMITTED_ALGO_ECDSA_SHA256;
	key_gen_args.key_type = HSM_KEY_TYPE_ECC_NIST;
	key_gen_args.bit_key_sz = HSM_KEY_SIZE_ECC_NIST_256;
	key_gen_args.out_size = 0;
	key_gen_args.out_key = NULL;

	err = hsm_generate_key(key_mgmt_hdl, &key_gen_args);
	if (err != HSM_NO_ERROR)
		printf("\nhsm_generate_key (Key ID #1) err: 0x%x\n", err);

	memset(&key_gen_args, 0, sizeof(key_gen_args));

	//Generate the Key to be used for the attestation, Key ID #2
	key_gen_args.key_identifier = &key_attestation_id;
	key_gen_args.key_lifecycle = 0;
	key_gen_args.key_group = 33;
	key_gen_args.key_lifetime = HSM_SE_KEY_STORAGE_VOLATILE;
	key_gen_args.key_usage = HSM_KEY_USAGE_SIGN_MSG |
				 HSM_KEY_USAGE_VERIFY_MSG;
	key_gen_args.permitted_algo = PERMITTED_ALGO_CMAC;
	key_gen_args.key_type = HSM_KEY_TYPE_AES;
	key_gen_args.bit_key_sz = HSM_KEY_SIZE_AES_256;
	key_gen_args.out_size = 0;
	key_gen_args.out_key = NULL;

	err = hsm_generate_key(key_mgmt_hdl, &key_gen_args);
	if (err != HSM_NO_ERROR)
		printf("\nhsm_generate_key (Key ID #2) err: 0x%x\n", err);

	//Public Key Attestation API test
	pub_key_attest_args.key_identifier = key_id;
	pub_key_attest_args.key_attestation_id = key_attestation_id;
	pub_key_attest_args.sign_algo = HSM_PKEY_ATTEST_ALGO_CMAC;
	pub_key_attest_args.auth_challenge = auth_challenge;
	pub_key_attest_args.auth_challenge_size = AUTH_CHALLENGE_SIZE;
	pub_key_attest_args.certificate = certificate;
	pub_key_attest_args.certificate_size = CERTIFICATE_SIZE;

	err = hsm_do_pub_key_attest(key_store_hdl, &pub_key_attest_args);
	printf("\nhsm_do_pub_key_attest err: 0x%x\n", err);

	key_management(DELETE, key_mgmt_hdl, &key_id, 32, HSM_KEY_TYPE_ECC_NIST);
	key_management(DELETE, key_mgmt_hdl, &key_attestation_id, 33, HSM_KEY_TYPE_AES);

	printf("\n------------------------------------------------\n");
	printf("Test Complete");
	printf("\n------------------------------------------------\n");
}
#endif
