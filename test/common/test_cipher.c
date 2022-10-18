/*
 * Copyright 2022 NXP
 *
 * NXP Confidential.
 * This software is owned or controlled by NXP and may only be used strictly
 * in accordance with the applicable license terms.  By expressly accepting
 * such terms or by downloading, installing, activating and/or otherwise using
 * the software, you are agreeing that you have read, and that you agree to
 * comply with and are bound by, such license terms.  If you do not agree to be
 * bound by the applicable license terms, then you may not retain, install,
 * activate or otherwise use the software.
 */

#include <stdio.h>

#include "hsm_api.h"

uint8_t hash_data[32] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F };


uint8_t iv_data[16] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

#define KEY_GROUP	1001

static hsm_err_t generate_key(hsm_hdl_t key_mgmt_hdl,
#ifdef CONFIG_PLAT_SECO
			      hsm_key_info_t key_info,
#else
			      hsm_key_lifetime_t key_lifetime,
			      hsm_key_usage_t key_usage,
			      hsm_permitted_algo_t permitted_algo,
#endif
			      hsm_key_type_t key_type,
			      uint32_t *key_identifier)
{
	op_generate_key_args_t key_gen_args = {0};

	key_gen_args.key_identifier = key_identifier;
	key_gen_args.out_size = 0;
	key_gen_args.key_group = KEY_GROUP;
#ifdef CONFIG_PLAT_SECO
	key_gen_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE;
	key_gen_args.key_info = key_info;
#else
	key_gen_args.key_lifetime = key_lifetime;
	key_gen_args.key_usage = key_usage;
	key_gen_args.permitted_algo = permitted_algo;
#endif
	key_gen_args.key_type = key_type;
	key_gen_args.out_key = NULL;

	return hsm_generate_key(key_mgmt_hdl, &key_gen_args);
}

hsm_err_t do_cipher_test(hsm_hdl_t key_store_hdl, hsm_hdl_t key_mgmt_hdl)
{
	op_cipher_one_go_args_t cipher_args = {0};
	hsm_hdl_t cipher_hdl;
	uint8_t ciphered_data[32] = {0};
	uint8_t deciphered_data[32] = {0};
	uint32_t sym_key_id;
	hsm_err_t hsmret;

	printf("---------------------------------------------------\n");
	printf("SECONDARY API: DO CIPHER Test Start\n");
	printf("---------------------------------------------------\n");

	generate_key(key_mgmt_hdl,
#ifndef PSA_COMPLIANT
			HSM_KEY_INFO_TRANSIENT,
#else
			HSM_HW_INTERN_STORAGE_VOLATILE,
			HSM_KEY_USAGE_DERIVE | HSM_KEY_USAGE_ENCRYPT | HSM_KEY_USAGE_DECRYPT,
			PERMITTED_ALGO_ALL_CIPHER,
#endif
			HSM_KEY_TYPE_AES_256, &sym_key_id);

	cipher_args.key_identifier = sym_key_id;
	cipher_args.iv = iv_data;
	cipher_args.iv_size = sizeof(iv_data);
#ifdef PSA_COMPLIANT
	cipher_args.cipher_algo = HSM_CIPHER_ONE_GO_ALGO_CBC;
#else
	cipher_args.cipher_algo = HSM_CIPHER_ONE_GO_ALGO_AES_CBC;
#endif
	cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_ENCRYPT;
	cipher_args.input = hash_data;
	cipher_args.output = ciphered_data;
	cipher_args.input_size = sizeof(hash_data);
	cipher_args.output_size = sizeof(ciphered_data);

	hsmret = hsm_do_cipher(key_store_hdl, &cipher_args);
	if (hsmret)
		printf("hsm_cipher_one_go ret:0x%x\n", hsmret);

	cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_DECRYPT;
	cipher_args.input = ciphered_data;
	cipher_args.output = deciphered_data;
	cipher_args.input_size = sizeof(ciphered_data);
	cipher_args.output_size = sizeof(deciphered_data);

	hsmret = hsm_do_cipher(key_store_hdl, &cipher_args);
	if (hsmret)
		printf("hsm_cipher_one_go ret:0x%x\n", hsmret);

	if (memcmp(hash_data, deciphered_data, sizeof(hash_data)) == 0)
		printf("\nDecrypted data matches encrypted data [PASS]\n");
	else
		printf("\nDecrypted data doesn't match encrypted data [FAIL]\n");

	printf("\n---------------------------------------------------\n");
	printf("SECONDARY API: DO CIPHER Test Complete\n");
	printf("---------------------------------------------------\n");

	return hsmret;
}
