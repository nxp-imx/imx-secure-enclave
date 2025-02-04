// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2025 NXP
 */

#include <stdio.h>

#include "test_common.h"
#include "hsm_api.h"

static uint8_t plaintext[32] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};

#ifdef PSA_COMPLIANT
static uint32_t key_exchange_helper(uint32_t key_mgmt_hdl,
				    hsm_op_key_exchange_flags_t flags,
				    uint8_t *in_content,
				    uint32_t in_content_sz,
				    uint8_t *in_pub_buffer,
				    uint32_t in_pub_buffer_sz,
				    uint8_t *user_fixed_info,
				    uint32_t user_fixed_info_sz,
				    uint8_t *output,
				    uint32_t output_sz)
{
	hsm_err_t err;
	op_key_exchange_args_t args = {0};

	args.flags = flags;
	args.in_content = in_content;
	args.in_content_sz = in_content_sz;
	args.in_pub_buffer = in_pub_buffer;
	args.in_pub_buffer_sz = in_pub_buffer_sz;
	args.user_fixed_info = user_fixed_info;
	args.user_fixed_info_sz = user_fixed_info_sz;
	args.output = output;
	args.output_sz = output_sz;

	err = hsm_key_exchange(key_mgmt_hdl, &args);
	printf("hsm_key_exchange [ECDH-HKDF] err: 0x%x\n", err);

	return err;
}

static uint32_t key_exchange_hkdf_helper(uint32_t key_mgmt_hdl,
					 uint32_t key_store_id,
					 uint32_t key_id)
{
	hsm_err_t err = HSM_GENERAL_ERROR;
	in_content_hkdf_args_t *in_content = NULL;
	uint32_t in_content_sz;
	op_key_exchange_args_t args = {0};
	uint8_t output_key_buffer[32] = {0};

	/* Prepare Input Plaintext Content */
	in_content_sz = sizeof(in_content_hkdf_args_t);
	in_content = (in_content_hkdf_args_t *)malloc(in_content_sz);

	if (!in_content) {
		printf("%s: failed to allocated memory\n", __func__);
		goto out;
	}

	memset(in_content, 0, in_content_sz);

	in_content->ver = 0x1;
	in_content->rsv = 0x0;
	in_content->keystore_id = key_store_id;
	in_content->key_id = key_id;
	in_content->hkdf_algo = HSM_KEY_DERIVATION_HKDF_SHA256;
	in_content->derived_key_type = HSM_KEY_TYPE_OEM_IMPORT_MK_SK;
	in_content->derived_key_bits_size = HSM_KEY_SIZE_OEM_IMPORT_MK_SK_256;
	in_content->derived_key_lifetime = HSM_SE_KEY_STORAGE_PERSISTENT;
	in_content->derived_key_usage = HSM_KEY_USAGE_DERIVE;
	in_content->derived_key_permitted_algo = HSM_KEY_DERIVATION_HKDF_SHA256;
	in_content->derived_key_lifecycle = 0x0; // Current lifecycle
	in_content->derived_key_id = 0x0; //ID to be chosen by FW
	in_content->buffer_len = 0x0;

	memset(&args, 0, sizeof(op_key_exchange_args_t));

	args.flags = HSM_OP_KEY_EXCHANGE_FLAGS_INPUT_PLAINTEXT_CONTENT;
	args.in_content_sz = in_content_sz;
	args.in_content = (uint8_t *)(in_content);
	args.in_pub_buffer_sz = sizeof(ecc_256_pub_key);
	args.in_pub_buffer = ecc_256_pub_key;
	args.user_fixed_info_sz = 0;
	args.user_fixed_info = NULL;

	err = hsm_key_exchange(key_mgmt_hdl, &args);
	printf("hsm_key_exchange [HKDF] err: 0x%x\n", err);

	memset(&args, 0, sizeof(op_key_exchange_args_t));

	args.flags = HSM_OP_KEY_EXCHANGE_FLAGS_INPUT_PLAINTEXT_CONTENT |
		     HSM_OP_KEY_EXCHANGE_FLAGS_RETURN_OUTPUT;
	args.in_content_sz = in_content_sz;
	args.in_content = (uint8_t *)(in_content);
	args.in_pub_buffer_sz = sizeof(ecc_256_pub_key);
	args.in_pub_buffer = ecc_256_pub_key;
	args.user_fixed_info_sz = 0;
	args.user_fixed_info = NULL;
	args.output_sz = sizeof(output_key_buffer);
	args.output = output_key_buffer;

	err = hsm_key_exchange(key_mgmt_hdl, &args);
	printf("hsm_key_exchange [HKDF][plainkey output] err: 0x%x\n", err);
out:
	return err;
}

uint8_t key_exchange_nxp_prod_key_test(uint32_t key_mgmt_hdl,
				       uint32_t key_store_id)
{
	hsm_err_t ret;
	uint8_t test_status = TEST_STATUS_FAILED;
	uint8_t *signed_content = NULL;
	uint32_t signed_content_len = 0;

	/*
	 * Signed Buffers have been generated with particular Key Store ID.
	 */
	if (key_store_id != TEST_KEYSTORE_ID)
		return TEST_STATUS_SKIPPED;

	printf("\n----------------------------------------\n");
	printf("Key Exchange (using NXP Prod key) test::\n");
	printf("----------------------------------------\n");

	/*
	 * Key Exchange (Unsigned)- HKDF using NXP PROD MANUFACT KEY AGREEMENT key.
	 * Expect FAILURE due to unsupported or restricted key attributes.
	 */
	ret = key_exchange_hkdf_helper(key_mgmt_hdl,
				       key_store_id,
				       TEST_KEY_NXP_PROD_MK_AGREEMENT);
	if (ret != HSM_KEY_NOT_SUPPORTED)
		goto out;

	/*
	 * Choose signed content buffer based on the board's OEM SRK type
	 */
	if (get_signed_tests_key_type() == SIGNED_TESTS_KEYS_TYPE_SECP521) {
		signed_content = signed_content_secp521_w_prod_key;
		signed_content_len = sizeof(signed_content_secp521_w_prod_key);
	} else if (get_signed_tests_key_type() == SIGNED_TESTS_KEYS_TYPE_SECP384) {
		signed_content = signed_content_secp384_w_prod_key;
		signed_content_len = sizeof(signed_content_secp384_w_prod_key);
	}

	/*
	 * Key Exchange (Signed) - OEM IMPORT MK SK gen using NXP PROD MANUFACT
	 * KEY AGREEMENT key.
	 * Expect SUCCESS.
	 */
	ret = key_exchange_helper(key_mgmt_hdl,
				  HSM_OP_KEY_EXCHANGE_FLAGS_INPUT_SIGNED_CONTENT,
				  signed_content,
				  signed_content_len,
				  ecc_256_pub_key,
				  sizeof(ecc_256_pub_key),
				  NULL,
				  0,
				  NULL,
				  0);
	if (ret != HSM_NO_ERROR)
		goto out;

	/*
	 * Key Exchange (Unsigned) - HKDF using NXP PROD MANUFACT KEY AGREEMENT key.
	 * Expect FAILURE due to unsupported or restricted key attributes.
	 */
	ret = key_exchange_hkdf_helper(key_mgmt_hdl,
				       key_store_id,
				       TEST_KEY_NXP_PROD_MK_AGREEMENT);
	if (ret != HSM_KEY_NOT_SUPPORTED)
		goto out;

	test_status = TEST_STATUS_SUCCESS;
out:
	if (test_status == TEST_STATUS_SUCCESS)
		printf("Result --> SUCCESS\n");
	else
		printf("Result --> FAILED\n");

	printf("----------------------------------------\n");

	return test_status;
}
#endif

hsm_err_t key_exchange_test(hsm_hdl_t hsm_session_hdl,
			    hsm_hdl_t key_store_hdl,
			    hsm_hdl_t key_mgmt_hdl)
{
	hsm_err_t err = HSM_GENERAL_ERROR;
	op_key_exchange_args_t key_exchange_args = {0};
#ifdef PSA_COMPLIANT
	op_generate_key_args_t key_gen_args = {0};
	op_cipher_one_go_args_t cipher_args = {0};
	uint8_t ciphertext[32] = {0};
	uint8_t deciphered_data[32] = {0};
	uint32_t key_id = KEY_EXCHANGE_PRIV_KEY_ID;
	uint8_t pubkey1[64] = {0}; //Public Key for ECC 256
#else
	uint32_t key_id_drv = 0;
	uint8_t work_area3[128] = {0};
	int j;
#endif

#ifdef PSA_COMPLIANT
	if (get_signed_tests_key_type() != SIGNED_TESTS_KEYS_TYPE_SECP384)
		return err;
#endif
	printf("\n------------------------------------------------\n");
	printf("Key Exchange API Test:");
	printf("\n------------------------------------------------\n");

#ifdef PSA_COMPLIANT
	memset(pubkey1, 0, sizeof(pubkey1));
	memset(&key_gen_args, 0, sizeof(key_gen_args));
	memset(&key_exchange_args, 0, sizeof(key_exchange_args));
	memset(&cipher_args, 0, sizeof(cipher_args));

	//Generate Persistent Asymmetric Key Pair with Given Key ID
	key_gen_args.key_identifier = &key_id;
	key_gen_args.key_group = 30;
	key_gen_args.key_lifetime = HSM_SE_KEY_STORAGE_PERSISTENT;
	key_gen_args.key_usage = HSM_KEY_USAGE_DERIVE;
	key_gen_args.permitted_algo = HSM_KEY_EXCHANGE_ECDH_HKDF_SHA256;
	key_gen_args.flags = HSM_OP_KEY_GENERATION_FLAGS_STRICT_OPERATION;
	key_gen_args.key_type = HSM_KEY_TYPE_ECC_NIST;
	key_gen_args.bit_key_sz = HSM_KEY_SIZE_ECC_NIST_256;
	key_gen_args.key_lifecycle = 0x0; //Current Device Lifecycle
	key_gen_args.out_key = pubkey1;
	key_gen_args.out_size = sizeof(pubkey1);

	err = hsm_generate_key(key_mgmt_hdl, &key_gen_args);
	printf("\nhsm_generate_key (KeyPair#1) err: 0x%x\n", err);

	if (err != HSM_NO_ERROR && err != HSM_ID_CONFLICT)
		goto out;

	//Use Key Exchange API to get Derived Key ID
	key_exchange_args.in_content = signed_content_buf;
	key_exchange_args.in_content_sz = sizeof(signed_content_buf);
	key_exchange_args.in_pub_buffer_sz = sizeof(peer_pubkey_buf);
	key_exchange_args.in_pub_buffer = peer_pubkey_buf;
	key_exchange_args.user_fixed_info_sz = 0;
	key_exchange_args.user_fixed_info = NULL;

	err = hsm_key_exchange(key_mgmt_hdl, &key_exchange_args);

	printf("\nhsm_key_exchange err: 0x%x\n", err);
	printf("\t--Derived Key ID: 0x%x\n", key_exchange_args.out_derived_key_id);
	printf("\t--Salt Size: 0x%x\n", key_exchange_args.out_salt_sz);
	if (err != HSM_NO_ERROR)
		goto out;

	//Perform Cipher operation (Encrypt) using Derived Key ID
	cipher_args.key_identifier = key_exchange_args.out_derived_key_id;
	cipher_args.iv = NULL;
	cipher_args.iv_size = 0;
	cipher_args.cipher_algo = HSM_CIPHER_ONE_GO_ALGO_ECB;
	cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_ENCRYPT;
	cipher_args.input = plaintext;
	cipher_args.output = ciphertext;
	cipher_args.input_size = sizeof(plaintext);
	cipher_args.output_size = sizeof(ciphertext);

	err = hsm_do_cipher(key_store_hdl, &cipher_args);
	if (err != HSM_NO_ERROR) {
		printf("hsm_cipher_one_go (ENCRYPT) err:0x%x\n", err);
		goto out;
	}

	//Perform Cipher operation (Decrypt) using Derived Key ID
	cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_DECRYPT;
	cipher_args.input = ciphertext;
	cipher_args.output = deciphered_data;
	cipher_args.input_size = sizeof(ciphertext);
	cipher_args.output_size = sizeof(deciphered_data);

	err = hsm_do_cipher(key_store_hdl, &cipher_args);
	if (err != HSM_NO_ERROR) {
		printf("hsm_cipher_one_go (DECRYPT) err:0x%x\n", err);
		goto out;
	}

	if (memcmp(plaintext, deciphered_data, sizeof(plaintext)) == 0)
		printf("\nDecrypted data matches Plaintext [PASS]\n");
	else
		printf("\nDecrypted data doesn't match Plaintext [FAIL]\n");
#else
	memset(&key_exchange_args, 0, sizeof(key_exchange_args));

	key_exchange_args.key_identifier = 0;
	key_exchange_args.shared_key_identifier_array = (uint8_t *)&key_id_drv;
	key_exchange_args.ke_input = ecc_p256_pubk;
	key_exchange_args.ke_output = work_area3;
	key_exchange_args.kdf_input = 0;
	key_exchange_args.kdf_output = 0;
	key_exchange_args.shared_key_group = 32;
	key_exchange_args.shared_key_info = HSM_KEY_INFO_KEK;
	key_exchange_args.shared_key_type = HSM_KEY_TYPE_AES_256;
	key_exchange_args.initiator_public_data_type = HSM_KEY_TYPE_ECDSA_NIST_P256;
	key_exchange_args.key_exchange_scheme = HSM_KE_SCHEME_ECDH_NIST_P256;
	key_exchange_args.kdf_algorithm = HSM_KDF_ONE_STEP_SHA_256;
	key_exchange_args.ke_input_size = 64;
	key_exchange_args.ke_output_size = 64;
	key_exchange_args.shared_key_identifier_array_size = 4;
	key_exchange_args.kdf_input_size = 0;
	key_exchange_args.kdf_output_size = 0;
	key_exchange_args.flags = HSM_OP_KEY_EXCHANGE_FLAGS_CREATE |
				  HSM_OP_KEY_EXCHANGE_FLAGS_GENERATE_EPHEMERAL;
	key_exchange_args.signed_message = NULL;
	key_exchange_args.signed_msg_size = 0;

	err = hsm_key_exchange(key_mgmt_hdl, &key_exchange_args);

	printf("Receiver pubk:\n");
	for (j = 0; j < 64; j++) {
		printf("0x%02x ", work_area3[j]);
		if (j % 16 == 15)
			printf("\n");
	}

	printf("Derived key_id 0x%08x\n", key_id_drv);

#endif
	printf("\n------------------------------------------------\n");
	printf("Test Complete");
	printf("\n------------------------------------------------\n");
out:
	return err;
}
