// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <stdio.h>

#include "hsm_api.h"

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


hsm_err_t auth_enc_test(hsm_hdl_t key_store_hdl, hsm_hdl_t key_mgmt_hdl)
{
	op_auth_enc_args_t auth_enc_args = {0};
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t key_id = 0;
#ifdef PSA_COMPLIANT
	printf("\n------------------------------------------------\n");
	printf("AUTH ENC Test:");
	printf("\n------------------------------------------------\n");

	generate_key(key_mgmt_hdl,
#ifndef PSA_COMPLIANT
			HSM_KEY_INFO_TRANSIENT,
			HSM_KEY_TYPE_AES_256,
#else
			HSM_SE_KEY_STORAGE_VOLATILE,
			HSM_KEY_USAGE_DERIVE | HSM_KEY_USAGE_ENCRYPT | HSM_KEY_USAGE_DECRYPT,
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

	printf("\n------------------------------------------------\n");
	printf("AUTH ENC Test: Complete");
	printf("\n------------------------------------------------\n");
#endif
	return err;
}
