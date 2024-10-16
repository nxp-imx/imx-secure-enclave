// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2024 NXP
 */

#include <stdio.h>

#include "hsm_api.h"
#include "test_common.h"

#ifdef PSA_COMPLIANT
#include "mbedtls_utils.h"
#endif

uint8_t hash_data[32] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F };


uint8_t iv_data[16] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

static uint8_t key[16] = {
	0x5D, 0xED, 0x4C, 0xA2, 0x34, 0xBC, 0x56, 0xCC,
	0xAD, 0x75, 0x57, 0xE0, 0x8F, 0xCB, 0x36, 0x4D,
};

#define KEY_GROUP	50

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
			      uint32_t *key_identifier)
{
	op_generate_key_args_t key_gen_args = {0};

	key_gen_args.key_identifier = key_identifier;
	key_gen_args.out_size = 0;
	key_gen_args.key_group = KEY_GROUP;
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

#ifdef PSA_COMPLIANT
hsm_err_t do_cipher_plainkey_test(hsm_hdl_t key_store_hdl, hsm_hdl_t key_mgmt_hdl)
{
	op_cipher_one_go_args_t args = {0};
	uint8_t ciphered_data[32] = {0};
	uint8_t deciphered_data[32] = {0};
	uint8_t mbedtls_ciphered_data[32] = {0};
	hsm_err_t hsmret;

	/* Plaintext Key Test */
	printf("\nPlaintext Key Test:\n");
	printf("---------------------\n");

	memset(&args, 0, sizeof(op_cipher_one_go_args_t));

	/* Cipher Encrypt */
	args.flags = HSM_CIPHER_ONE_GO_FLAGS_ENCRYPT | HSM_CIPHER_FLAGS_PLAINTEXT_KEY;
	args.cipher_algo = HSM_CIPHER_ONE_GO_ALGO_CBC;
	args.key = key;
	args.key_size = sizeof(key);
	args.key_type = HSM_KEY_TYPE_AES;
	args.iv = iv_data;
	args.iv_size = sizeof(iv_data);
	args.input = hash_data;
	args.input_size = sizeof(hash_data);
	args.output = ciphered_data;
	args.output_size = sizeof(ciphered_data);

	hsmret = hsm_do_cipher(key_store_hdl, &args);
	printf("hsm_do_cipher (encrypt) ret:0x%x\n", hsmret);

	/* Cipher Decrypt */
	args.flags = HSM_CIPHER_ONE_GO_FLAGS_DECRYPT | HSM_CIPHER_FLAGS_PLAINTEXT_KEY;
	args.input = ciphered_data;
	args.input_size = sizeof(ciphered_data);
	args.output = deciphered_data;
	args.output_size = sizeof(deciphered_data);

	hsmret = hsm_do_cipher(key_store_hdl, &args);
	printf("hsm_do_cipher (decrypt) ret:0x%x\n", hsmret);

	if (memcmp(hash_data, deciphered_data, sizeof(hash_data)) == 0)
		printf("\nDecrypted data matches encrypted data [PASS]\n");
	else
		printf("\nDecrypted data doesn't match encrypted data [FAIL]\n");

	/* Mbed-TLS cipher operation */
	my_mbedtls_aes_cbc(HSM_KEY_SIZE_AES_128, key,
			   HSM_CIPHER_ONE_GO_FLAGS_ENCRYPT,
			   hash_data, sizeof(hash_data),
			   mbedtls_ciphered_data,
			   iv_data);

	if (memcmp(ciphered_data, mbedtls_ciphered_data, sizeof(ciphered_data)) == 0)
		printf("\nCiphertext validation with Mbed-TLS [PASS]\n");
	else
		printf("\nCiphertext validation with Mbed-TLS [FAIL]\n");

	return hsmret;
}
#endif

hsm_err_t do_cipher_test(hsm_hdl_t key_store_hdl, hsm_hdl_t key_mgmt_hdl)
{
	op_cipher_one_go_args_t cipher_args = {0};
	hsm_hdl_t cipher_hdl;
	uint8_t ciphered_data[32] = {0};
	uint8_t deciphered_data[32] = {0};
	uint32_t sym_key_id = 0;
	hsm_err_t hsmret;

	printf("---------------------------------------------------\n");
	printf("SECONDARY API: DO CIPHER Test Start\n");
	printf("---------------------------------------------------\n");

	/* Opaque Key Test */
	printf("\nOpaque Key Test\n");
	printf("-----------------\n");

	generate_key(key_mgmt_hdl,
#ifndef PSA_COMPLIANT
			HSM_KEY_INFO_TRANSIENT,
			HSM_KEY_TYPE_AES_256,
#else
			HSM_SE_KEY_STORAGE_VOLATILE,
			HSM_KEY_USAGE_ENCRYPT | HSM_KEY_USAGE_DECRYPT,
			PERMITTED_ALGO_ALL_CIPHER,
			HSM_KEY_SIZE_AES_256,
			0,
			HSM_KEY_TYPE_AES,
#endif
			&sym_key_id);

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

#ifdef PSA_COMPLIANT
	hsmret = do_cipher_plainkey_test(key_store_hdl, key_mgmt_hdl);
#endif
	printf("\n---------------------------------------------------\n");
	printf("SECONDARY API: DO CIPHER Test Complete\n");
	printf("---------------------------------------------------\n");

	return hsmret;
}
