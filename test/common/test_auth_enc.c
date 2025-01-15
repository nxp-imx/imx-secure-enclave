// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2025 NXP
 */

#include <stdio.h>

#include "hsm_api.h"
#include "test_common.h"

static uint8_t test_message[32] = {
	0xB2, 0xE1, 0x4C, 0x5C, 0x79, 0xC6, 0xDF, 0x5B, 0x85, 0xF4, 0xFE, 0x7E,
	0xD8, 0xDB, 0x7A, 0x26, 0x2B, 0x9D, 0xA7, 0xE0, 0x7C, 0xCB, 0x0E, 0xA9,
	0xF4, 0x74, 0x7B, 0x8C, 0xCD, 0xA8, 0xA4, 0xF3,};

static uint8_t iv_data[12] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
	};

static uint8_t aad_data[16] = {
	0x85, 0xF4, 0xFE, 0x7E, 0xD8, 0xDB, 0x7A, 0x26, 0x2B, 0x9D, 0xA7, 0xE0,
	0x7C, 0xCB, 0x0E, 0xA9,};

static uint8_t testcase_ccm_aes128key[16] = {
	0x5D, 0xED, 0x4C, 0xA2, 0x34, 0xBC, 0x56, 0xCC,
	0xAD, 0x75, 0x57, 0xE0, 0x8F, 0xCB, 0x36, 0x4D,
};

static uint8_t ciphertext[48] = {0};
static uint8_t plaintext[32] = {0};

static hsm_err_t generate_key(hsm_hdl_t key_mgmt_hdl,
#ifndef PSA_COMPLIANT
				hsm_key_info_t key_info,
#else
				hsm_key_lifetime_t key_lifetime,
				hsm_key_usage_t key_usage,
				hsm_permitted_algo_t permitted_algo,
				hsm_bit_key_sz_t bit_key_sz,
				hsm_key_lifecycle_t key_lifecycle,
#endif
				hsm_key_type_t key_type,
				hsm_key_group_t key_group,
				uint32_t *key_identifier)
{
	op_generate_key_args_t key_gen_args = {0};

	key_gen_args.key_identifier = key_identifier;
	key_gen_args.out_size = 0;
	key_gen_args.key_group = key_group;
#ifndef PSA_COMPLIANT
	key_gen_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE;
	key_gen_args.key_info = key_info;
#else
	key_gen_args.key_lifetime = key_lifetime;
	key_gen_args.key_usage = key_usage;
	key_gen_args.permitted_algo = permitted_algo;
	key_gen_args.bit_key_sz = bit_key_sz;
	key_gen_args.key_lifecycle = key_lifecycle;
#endif
	key_gen_args.key_type = key_type;
	key_gen_args.out_key = NULL;

	return hsm_generate_key(key_mgmt_hdl, &key_gen_args);
}

static hsm_err_t auth_enc_test_chacha20_poly1305(hsm_hdl_t key_store_hdl,
						 hsm_hdl_t key_mgmt_hdl)
{
	op_generate_key_args_t key_gen_args = {0};
	op_delete_key_args_t del_args = {0};
	op_auth_enc_args_t auth_enc_args = {0};
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t key_id = 0;
#ifdef PSA_COMPLIANT
	printf("\nCHACHA20_POLY1305:\n\n");

	/* 1. Generate Key permitted for CHACHA20_POLY1305  */
	memset(&key_gen_args, 0, sizeof(op_generate_key_args_t));

	key_gen_args.key_identifier = &key_id;
	key_gen_args.key_group = 50;
	key_gen_args.key_lifetime = HSM_SE_KEY_STORAGE_VOLATILE;
	key_gen_args.permitted_algo = PERMITTED_ALGO_CHACHA20_POLY1305;
	key_gen_args.key_usage = HSM_KEY_USAGE_ENCRYPT | HSM_KEY_USAGE_DECRYPT;
	key_gen_args.key_type = HSM_KEY_TYPE_AES;
	key_gen_args.bit_key_sz = HSM_KEY_SIZE_AES_256;
	key_gen_args.key_lifecycle = 0x0;
	key_gen_args.out_size = 0;
	key_gen_args.out_key = NULL;

	err = hsm_generate_key(key_mgmt_hdl, &key_gen_args);
	if (err != HSM_NO_ERROR)
		printf("hsm_generate_key ret: 0x%x\n", err);

	/* 2. Perform Authenticated Encryption operation (Encrypt) */
	memset(&auth_enc_args, 0, sizeof(op_auth_enc_args_t));

	auth_enc_args.key_identifier = key_id;
	auth_enc_args.iv_size = sizeof(iv_data);
	auth_enc_args.iv = iv_data;
	auth_enc_args.ae_algo = HSM_AEAD_ALGO_CHACHA20_POLY1305;
	auth_enc_args.flags = HSM_AUTH_ENC_FLAGS_ENCRYPT;
	auth_enc_args.aad_size = sizeof(aad_data);
	auth_enc_args.aad = aad_data;
	auth_enc_args.input_size = sizeof(test_message);
	auth_enc_args.input = test_message;
	auth_enc_args.output_size = sizeof(ciphertext);
	auth_enc_args.output = ciphertext;

	err = hsm_do_auth_enc(key_store_hdl, &auth_enc_args);
	printf("hsm_do_auth_enc (Encrypt) ret: 0x%x\n", err);

	if (err == HSM_OUT_TOO_SMALL)
		printf("Expected Output Size (Encrypt): %d\n",
		       auth_enc_args.exp_output_size);

	/* 3. Perform Authenticated Encryption operation (Decrypt) */
	auth_enc_args.flags = HSM_AUTH_ENC_FLAGS_DECRYPT;
	auth_enc_args.input_size = sizeof(ciphertext);
	auth_enc_args.input = ciphertext;
	auth_enc_args.output_size = sizeof(plaintext);
	auth_enc_args.output = plaintext;

	err = hsm_do_auth_enc(key_store_hdl, &auth_enc_args);
	printf("hsm_do_auth_enc (Decrypt) ret: 0x%x\n", err);

	if (err == HSM_OUT_TOO_SMALL)
		printf("Expected Output Size (Decrypt): %d\n",
		       auth_enc_args.exp_output_size);

	if (memcmp(test_message, plaintext, sizeof(test_message)) == 0)
		printf("\nAuth Enc: Decrypted data matches Test data [PASS]\n");
	else
		printf("\nAuth Enc: Decrypted data doesn't match Test data [FAIL]\n");

	/* 4. Delete the Generated Test Key */
	memset(&del_args, 0, sizeof(del_args));

	del_args.key_identifier = key_id;
	del_args.flags = 0;
	err = hsm_delete_key(key_mgmt_hdl, &del_args);
	if (err != HSM_NO_ERROR)
		printf("hsm_delete_key ret: 0x%x\n", err);

#endif
	return err;
}

static hsm_err_t auth_enc_test_ccm(hsm_hdl_t key_store_hdl,
				   hsm_hdl_t key_mgmt_hdl)
{
	op_auth_enc_args_t auth_enc_args = {0};
	op_delete_key_args_t del_args = {0};
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t key_id = 0;
#ifdef PSA_COMPLIANT
	printf("\nCCM:\n\n");

	generate_key(key_mgmt_hdl,
#ifndef PSA_COMPLIANT
			HSM_KEY_INFO_TRANSIENT,
			HSM_KEY_TYPE_AES_256,
#else
			HSM_SE_KEY_STORAGE_VOLATILE,
			HSM_KEY_USAGE_ENCRYPT | HSM_KEY_USAGE_DECRYPT,
			PERMITTED_ALGO_CCM,
			HSM_KEY_SIZE_AES_256,
			0,
			HSM_KEY_TYPE_AES,
#endif
			50,
			&key_id);

	auth_enc_args.key_identifier = key_id;
	auth_enc_args.iv_size = sizeof(iv_data);
	auth_enc_args.iv = iv_data;
	auth_enc_args.ae_algo = HSM_AEAD_ALGO_CCM;
	auth_enc_args.flags = HSM_AUTH_ENC_FLAGS_ENCRYPT;
	auth_enc_args.aad_size = sizeof(aad_data);
	auth_enc_args.aad = aad_data;
	auth_enc_args.input_size = sizeof(test_message);
	auth_enc_args.input = test_message;
	auth_enc_args.output_size = sizeof(ciphertext);
	auth_enc_args.output = ciphertext;

	err = hsm_do_auth_enc(key_store_hdl, &auth_enc_args);
	printf("hsm_do_auth_enc (Encrypt) ret: 0x%x\n", err);

	if (err == HSM_OUT_TOO_SMALL)
		printf("Expected Output Size (Encrypt): %d\n",
		       auth_enc_args.exp_output_size);

	auth_enc_args.flags = HSM_AUTH_ENC_FLAGS_DECRYPT;
	auth_enc_args.input_size = sizeof(ciphertext);
	auth_enc_args.input = ciphertext;
	auth_enc_args.output_size = sizeof(plaintext);
	auth_enc_args.output = plaintext;

	err = hsm_do_auth_enc(key_store_hdl, &auth_enc_args);
	printf("hsm_do_auth_enc (Decrypt) ret: 0x%x\n", err);

	if (err == HSM_OUT_TOO_SMALL)
		printf("Expected Output Size (Decrypt): %d\n",
		       auth_enc_args.exp_output_size);

	if (memcmp(test_message, plaintext, sizeof(test_message)) == 0)
		printf("\nAuth Enc: Decrypted data matches Test data [PASS]\n");
	else
		printf("\nAuth Enc: Decrypted data doesn't match Test data [FAIL]\n");

	/* Delete the Generated Test Key */
	memset(&del_args, 0, sizeof(del_args));

	del_args.key_identifier = key_id;
	del_args.flags = 0;
	err = hsm_delete_key(key_mgmt_hdl, &del_args);
	if (err != HSM_NO_ERROR)
		printf("hsm_delete_key ret: 0x%x\n", err);
#endif
	return err;
}

#ifdef PSA_COMPLIANT
static hsm_err_t auth_enc_new_ccm_test(hsm_hdl_t key_store_hdl,
				       hsm_hdl_t key_mgmt_hdl)
{
	hsm_err_t err = HSM_GENERAL_ERROR;
	op_auth_enc_new_args_t args = {0};
	op_delete_key_args_t del_args = {0};
	uint32_t key_id = 0;
	uint8_t ciphertext[32] = {0};
	uint8_t plaintext[32] = {0};
	uint8_t tag[16] = {0};

	printf("\nOpaque Key Test (CCM):\n");
	printf("------------------------\n");

	/* Generate key for the operation */
	err = generate_key(key_mgmt_hdl,
			   HSM_SE_KEY_STORAGE_VOLATILE,
			   HSM_KEY_USAGE_ENCRYPT | HSM_KEY_USAGE_DECRYPT,
			   PERMITTED_ALGO_CCM,
			   HSM_KEY_SIZE_AES_256,
			   0,
			   HSM_KEY_TYPE_AES,
			   50,
			   &key_id);
	if (err != HSM_NO_ERROR)
		goto out;

	/* AEAD Encrypt operation using opaque key */
	memset(&args, 0, sizeof(op_auth_enc_new_args_t));

	args.key_id = key_id;
	args.flags = HSM_AUTH_ENC_FLAGS_ENCRYPT | HSM_AUTH_ENC_FLAGS_ONE_SHOT;
	args.ae_algo = HSM_AEAD_ALGO_CCM;
	args.input_size = sizeof(test_message);
	args.input = test_message;
	args.output_size = sizeof(ciphertext);
	args.output = ciphertext;
	args.iv_size = sizeof(iv_data);
	args.iv_in = iv_data;
	args.aad_size = sizeof(aad_data);
	args.aad = aad_data;
	args.tag_size = sizeof(tag);
	args.tag = tag;

	err = hsm_do_auth_enc_new(key_store_hdl, &args);
	printf("hsm_do_auth_enc_new (Encrypt) ret: 0x%x\n", err);
	if (err == HSM_OUT_TOO_SMALL)
		printf("Expected Output Size (Encrypt): %d\n", args.exp_output_size);

	/* AEAD Decrypt operation using Opaque key */
	args.flags = HSM_AUTH_ENC_FLAGS_DECRYPT | HSM_AUTH_ENC_FLAGS_ONE_SHOT;
	args.input_size = sizeof(ciphertext);
	args.input = ciphertext;
	args.output_size = sizeof(plaintext);
	args.output = plaintext;

	err = hsm_do_auth_enc_new(key_store_hdl, &args);
	printf("hsm_do_auth_enc_new (Decrypt) ret: 0x%x\n", err);
	if (err == HSM_OUT_TOO_SMALL)
		printf("Expected Output Size (Decrypt): %d\n", args.exp_output_size);

	if (memcmp(test_message, plaintext, sizeof(test_message)) == 0)
		printf("\nDecrypted data matches Test data [PASS]\n");
	else
		printf("\nDecrypted data doesn't match Test data [FAIL]\n");

	/* Delete the Generated Test Key */
	memset(&del_args, 0, sizeof(del_args));

	del_args.key_identifier = key_id;
	del_args.flags = 0;
	err = hsm_delete_key(key_mgmt_hdl, &del_args);
	if (err != HSM_NO_ERROR)
		printf("hsm_delete_key ret: 0x%x\n", err);
out:
	return err;
}

static hsm_err_t auth_enc_new_ccm_plainkey_test(hsm_hdl_t key_store_hdl,
						hsm_hdl_t key_mgmt_hdl)
{
	hsm_err_t err = HSM_GENERAL_ERROR;
	op_auth_enc_new_args_t args = {0};
	uint8_t ciphertext[32] = {0};
	uint8_t plaintext[32] = {0};
	uint8_t tag[16] = {0};

	printf("\nPlainkey Test (CCM):\n");
	printf("----------------------\n");

	/* AEAD Encrypt operation using Plaintext key */
	args.ae_algo = HSM_AEAD_ALGO_CCM;
	args.flags = HSM_AUTH_ENC_FLAGS_ENCRYPT | HSM_AUTH_ENC_FLAGS_ONE_SHOT |
		     HSM_AUTH_ENC_FLAGS_PLAINTEXT_KEY;
	args.key = testcase_ccm_aes128key;
	args.key_size = BITS_TO_BYTES(HSM_KEY_SIZE_AES_128);
	args.key_type = HSM_KEY_TYPE_AES;
	args.input_size = sizeof(test_message);
	args.input = test_message;
	args.output_size = sizeof(ciphertext);
	args.output = ciphertext;
	args.iv_size = sizeof(iv_data);
	args.iv_in = iv_data;
	args.aad_size = sizeof(aad_data);
	args.aad = aad_data;
	args.tag_size = sizeof(tag);
	args.tag = tag;

	err = hsm_do_auth_enc_new(key_store_hdl, &args);
	printf("hsm_do_auth_enc_new (Encrypt) ret: 0x%x\n", err);
	if (err == HSM_OUT_TOO_SMALL)
		printf("Expected Output Size (Encrypt): %d\n", args.exp_output_size);

	/* AEAD Decrypt operation using Plaintext key */
	args.flags = HSM_AUTH_ENC_FLAGS_DECRYPT | HSM_AUTH_ENC_FLAGS_ONE_SHOT |
		     HSM_AUTH_ENC_FLAGS_PLAINTEXT_KEY;
	args.input_size = sizeof(ciphertext);
	args.input = ciphertext;
	args.output_size = sizeof(plaintext);
	args.output = plaintext;

	err = hsm_do_auth_enc_new(key_store_hdl, &args);
	printf("hsm_do_auth_enc_new (Decrypt) ret: 0x%x\n", err);
	if (err == HSM_OUT_TOO_SMALL)
		printf("Expected Output Size (Decrypt): %d\n", args.exp_output_size);

	if (memcmp(test_message, plaintext, sizeof(plaintext)) == 0)
		printf("\nDecrypted data matches Test data [PASS]\n");
	else
		printf("\nDecrypted data doesn't match Test data [FAIL]\n");

	return err;
}

static hsm_err_t auth_enc_new_ccm_stream_test(hsm_hdl_t key_store_hdl,
					      hsm_hdl_t key_mgmt_hdl)
{
	hsm_err_t err;
	open_svc_cipher_args_t open_cipher_args = {0};
	op_auth_enc_new_args_t args = {0};
	hsm_hdl_t cipher_hdl = 0;
	uint32_t key_id = 0;
	uint8_t ciphertext[32] = {0};
	uint8_t plaintext[32] = {0};
	uint8_t tag[16] = {0};

	printf("\nCCM Streaming Test - Opaque Key:\n");
	printf("----------------------------------\n");

	/* Generate key for the operation */
	err = generate_key(key_mgmt_hdl,
			   HSM_SE_KEY_STORAGE_VOLATILE,
			   HSM_KEY_USAGE_ENCRYPT | HSM_KEY_USAGE_DECRYPT,
			   PERMITTED_ALGO_CCM,
			   HSM_KEY_SIZE_AES_256,
			   0,
			   HSM_KEY_TYPE_AES,
			   50,
			   &key_id);
	if (err != HSM_NO_ERROR)
		goto out;

	/* Open Cipher Service.
	 * Multipart opaque operation needs to one cipher handle per operation.
	 */

	err = hsm_open_cipher_service(key_store_hdl, &open_cipher_args, &cipher_hdl);
	if (err != HSM_NO_ERROR) {
		printf("\nhsm_open_cipher_service err: 0x%x\n", err);
		goto out;
	}

	/* AEAD ENCRYPT (Streaming) */

	/* INIT */
	memset(&args, 0, sizeof(op_auth_enc_new_args_t));
	args.flags = HSM_AUTH_ENC_FLAGS_ENCRYPT | HSM_AUTH_ENC_FLAGS_INIT;
	args.key_id = key_id;
	args.ae_algo = HSM_AEAD_ALGO_CCM;
	args.iv_size = sizeof(iv_data);
	args.iv_in = iv_data;
	args.aad_size = sizeof(aad_data);
	args.input_size = sizeof(test_message);

	err = hsm_auth_enc_new(cipher_hdl, &args);
	if (err != HSM_NO_ERROR) {
		printf("\nhsm_auth_enc_new (encrypt) (INIT) err: 0x%x\n", err);
		goto out;
	}

	/* UPDATE AAD */
	memset(&args, 0, sizeof(op_auth_enc_new_args_t));
	args.flags = HSM_AUTH_ENC_FLAGS_ENCRYPT | HSM_AUTH_ENC_FLAGS_UPDATE_AAD;
	args.ae_algo = HSM_AEAD_ALGO_CCM;
	args.aad_size = sizeof(aad_data);
	args.aad = aad_data;

	err = hsm_auth_enc_new(cipher_hdl, &args);
	if (err != HSM_NO_ERROR) {
		printf("\nhsm_auth_enc_new (encrypt) (UPDATE AAD) err: 0x%x\n", err);
		goto out;
	}

	/* UPDATE DATA */
	memset(&args, 0, sizeof(op_auth_enc_new_args_t));
	args.flags = HSM_AUTH_ENC_FLAGS_ENCRYPT | HSM_AUTH_ENC_FLAGS_UPDATE_DATA;
	args.ae_algo = HSM_AEAD_ALGO_CCM;
	args.input_size = sizeof(test_message);
	args.input = test_message;
	args.output_size = sizeof(ciphertext);
	args.output = ciphertext;

	err = hsm_auth_enc_new(cipher_hdl, &args);
	if (err != HSM_NO_ERROR) {
		printf("\nhsm_auth_enc_new (encrypt) (UPDATE DATA) err: 0x%x\n", err);
		goto out;
	}

	/* FINALIZE */
	memset(&args, 0, sizeof(op_auth_enc_new_args_t));
	args.flags = HSM_AUTH_ENC_FLAGS_ENCRYPT | HSM_AUTH_ENC_FLAGS_FINALIZE;
	args.ae_algo = HSM_AEAD_ALGO_CCM;
	args.tag_size = sizeof(tag);
	args.tag = tag;

	err = hsm_auth_enc_new(cipher_hdl, &args);
	if (err != HSM_NO_ERROR) {
		printf("\nhsm_auth_enc_new (encrypt) (FINALIZE) err: 0x%x\n", err);
		goto out;
	}

	/* AEAD DECRYPT (Streaming) */

	/* INIT */
	memset(&args, 0, sizeof(op_auth_enc_new_args_t));
	args.flags = HSM_AUTH_ENC_FLAGS_DECRYPT | HSM_AUTH_ENC_FLAGS_INIT;
	args.key_id = key_id;
	args.ae_algo = HSM_AEAD_ALGO_CCM;
	args.iv_size = sizeof(iv_data);
	args.iv_in = iv_data;
	args.aad_size = sizeof(aad_data);
	args.input_size = sizeof(ciphertext);

	err = hsm_auth_enc_new(cipher_hdl, &args);
	if (err != HSM_NO_ERROR) {
		printf("\nhsm_auth_enc_new (decrypt) (INIT) err: 0x%x\n", err);
		goto out;
	}

	/* UPDATE AAD */
	memset(&args, 0, sizeof(op_auth_enc_new_args_t));
	args.flags = HSM_AUTH_ENC_FLAGS_DECRYPT | HSM_AUTH_ENC_FLAGS_UPDATE_AAD;
	args.ae_algo = HSM_AEAD_ALGO_CCM;
	args.aad_size = sizeof(aad_data);
	args.aad = aad_data;

	err = hsm_auth_enc_new(cipher_hdl, &args);
	if (err != HSM_NO_ERROR) {
		printf("\nhsm_auth_enc_new (decrypt) (UPDATE AAD) err: 0x%x\n", err);
		goto out;
	}

	/* UPDATE DATA */
	memset(&args, 0, sizeof(op_auth_enc_new_args_t));
	args.flags = HSM_AUTH_ENC_FLAGS_DECRYPT | HSM_AUTH_ENC_FLAGS_UPDATE_DATA;
	args.ae_algo = HSM_AEAD_ALGO_CCM;
	args.input_size = sizeof(ciphertext);
	args.input = ciphertext;
	args.output_size = sizeof(plaintext);
	args.output = plaintext;

	err = hsm_auth_enc_new(cipher_hdl, &args);
	if (err != HSM_NO_ERROR) {
		printf("\nhsm_auth_enc_new (decrypt) (UPDATE DATA) err: 0x%x\n", err);
		goto out;
	}

	/* FINALIZE VERIFY */
	memset(&args, 0, sizeof(op_auth_enc_new_args_t));
	args.flags = HSM_AUTH_ENC_FLAGS_DECRYPT | HSM_AUTH_ENC_FLAGS_FINALIZE_VERIFY;
	args.ae_algo = HSM_AEAD_ALGO_CCM;
	args.tag_size = sizeof(tag);
	args.tag = tag;

	err = hsm_auth_enc_new(cipher_hdl, &args);
	if (err != HSM_NO_ERROR) {
		printf("\nhsm_auth_enc_new (decrypt) (FINALIZE VERIFY) err: 0x%x\n", err);
		goto out;
	}

	/* Close the Cipher Service */
	err = hsm_close_cipher_service(cipher_hdl);
	if (err != HSM_NO_ERROR) {
		printf("\nhsm_close_cipher_service err: 0x%x\n", err);
		goto out;
	}

	if (args.verify_status == HSM_AEAD_VERIFICATION_STATUS_SUCCESS &&
	    memcmp(test_message, plaintext, sizeof(plaintext)) == 0)
		printf("\nDecrypted data matches Test data [PASS]\n");
	else
		printf("\nDecrypted data doesn't match Test data [FAIL]\n");

out:
	if (key_id)
		delete_test_key(key_mgmt_hdl, key_id, 0);

	return err;
}
#endif

hsm_err_t auth_enc_test(hsm_hdl_t key_store_hdl, hsm_hdl_t key_mgmt_hdl)
{
#ifdef PSA_COMPLIANT
	printf("\n------------------------------------------------\n");
	printf("AUTH ENC (legacy) Test:");
	printf("\n------------------------------------------------\n");

	auth_enc_test_ccm(key_store_hdl, key_mgmt_hdl);

	if (se_get_soc_id() != SOC_IMX8ULP &&
	    se_get_soc_id() != SOC_IMX95 &&
	    se_get_soc_id() != SOC_IMX943)
		auth_enc_test_chacha20_poly1305(key_store_hdl, key_mgmt_hdl);

	printf("\n------------------------------------------------\n");
	printf("Test Complete");
	printf("\n------------------------------------------------\n");

	printf("\n------------------------------------------------\n");
	printf("AUTH ENC (New) Tests:");
	printf("\n------------------------------------------------\n");

	auth_enc_new_ccm_test(key_store_hdl, key_mgmt_hdl);
	auth_enc_new_ccm_plainkey_test(key_store_hdl, key_mgmt_hdl);

	if (se_get_soc_id() == SOC_IMX95 ||
	    se_get_soc_id() == SOC_IMX943)
		auth_enc_new_ccm_stream_test(key_store_hdl, key_mgmt_hdl);

	printf("\n------------------------------------------------\n");
	printf("Test Complete");
	printf("\n------------------------------------------------\n");
#endif
}
