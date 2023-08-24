// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <string.h>
#include "she_api.h"
#include "plat_utils.h"

she_err_t she_ecb_test(she_hdl_t cipher_handle)
{
	op_cipher_one_go_args_t cipher_args = {0};
	uint8_t hash_data[16] = {0x7f, 0x4e, 0x91, 0xa2, 0x01, 0x1a, 0x6d, 0x57,
				 0x4e, 0x1e, 0x80, 0x43, 0x17, 0x88, 0x38, 0xce};
	uint8_t ciphered_data[16] = {0};
	uint8_t expected_data[16] = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
				     0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};
	uint8_t deciphered_data[16] = {0};
	uint8_t i = 0;

	she_err_t err;

	/* Encrypt operation */
	cipher_args.key_identifier = SHE_KEY_10;
	cipher_args.iv = NULL;
	cipher_args.iv_size = 0u;
	cipher_args.cipher_algo = SHE_CIPHER_ONE_GO_ALGO_AES_ECB;
	cipher_args.flags = SHE_CIPHER_ONE_GO_FLAGS_ENCRYPT;
	cipher_args.input = hash_data;
	cipher_args.output = ciphered_data;
	cipher_args.input_size = sizeof(hash_data);
	cipher_args.output_size = sizeof(ciphered_data);

	se_print("--- ECB CIPHER TEST STARTED ---\n");
	err = she_cipher_one_go(cipher_handle, &cipher_args);
	if (err) {
		se_print("ECB Encrypt: ret:0x%x ---> TEST FAILED\n", err);
		return err;
	}

	for (i = 0; i < 16; i++) {
		if ((i % 10) == 0)
			printf("\n");
		printf("%02x:%02x ", cipher_args.output[i], expected_data[i]);
	}

	/* Decrypt operation */
	memset(&deciphered_data, 0, sizeof(deciphered_data));
	memset(&cipher_args, 0, sizeof(cipher_args));
	cipher_args.key_identifier = SHE_KEY_10;
	cipher_args.iv = NULL;
	cipher_args.iv_size = 0u;
	cipher_args.cipher_algo = SHE_CIPHER_ONE_GO_ALGO_AES_ECB;
	cipher_args.flags = SHE_CIPHER_ONE_GO_FLAGS_DECRYPT;
	cipher_args.input = ciphered_data;
	cipher_args.output = deciphered_data;
	cipher_args.input_size = sizeof(ciphered_data);
	cipher_args.output_size = sizeof(deciphered_data);

	err = she_cipher_one_go(cipher_handle, &cipher_args);
	if (err) {
		se_print("ECB Decrypt: ret:0x%x ---> TEST FAILED\n", err);
		return err;
	}

	for (i = 0; i < 16; i++) {
		if ((i % 10) == 0)
			printf("\n");
		printf("%02x:%02x ", cipher_args.output[i], hash_data[i]);
	}

	if (memcmp(hash_data, cipher_args.output, sizeof(hash_data)) != 0)
		se_print("Decrypted data doesn't match encrypted data [FAIL]\n");

	return err;
}

she_err_t she_cbc_test(she_hdl_t cipher_handle)
{
	op_cipher_one_go_args_t cipher_args = {0};
	uint8_t iv_data[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			       0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
	uint8_t hash_data[16] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
				 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
	uint8_t ciphered_data[16] = {0};
	uint8_t expected_data[16] = {0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
				     0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d};
	uint8_t deciphered_data[16] = {0};
	uint8_t i = 0;

	she_err_t err;

	/* Encrypt operation */
	cipher_args.key_identifier = SHE_KEY_10;
	cipher_args.iv = iv_data;
	cipher_args.iv_size = sizeof(iv_data);
	cipher_args.cipher_algo = SHE_CIPHER_ONE_GO_ALGO_AES_CBC;
	cipher_args.flags = SHE_CIPHER_ONE_GO_FLAGS_ENCRYPT;
	cipher_args.input = hash_data;
	cipher_args.output = ciphered_data;
	cipher_args.input_size = sizeof(hash_data);
	cipher_args.output_size = sizeof(ciphered_data);

	se_print("--- CBC CIPHER TEST STARTED ---\n");
	err = she_cipher_one_go(cipher_handle, &cipher_args);
	if (err) {
		se_print("CBC Encrypt: ret:0x%x ---> TEST FAILED\n", err);
		return err;
	}

	for (i = 0; i < 16; i++) {
		if ((i % 10) == 0)
			printf("\n");
		printf("%02x:%02x ", cipher_args.output[i], expected_data[i]);
	}

	/* Decrypt operation */
	memset(&deciphered_data, 0, sizeof(deciphered_data));
	memset(&cipher_args, 0, sizeof(cipher_args));
	cipher_args.key_identifier = SHE_KEY_10;
	cipher_args.iv = iv_data;
	cipher_args.iv_size = sizeof(iv_data);
	cipher_args.cipher_algo = SHE_CIPHER_ONE_GO_ALGO_AES_CBC;
	cipher_args.flags = SHE_CIPHER_ONE_GO_FLAGS_DECRYPT;
	cipher_args.input = ciphered_data;
	cipher_args.output = deciphered_data;
	cipher_args.input_size = sizeof(ciphered_data);
	cipher_args.output_size = sizeof(deciphered_data);

	err = she_cipher_one_go(cipher_handle, &cipher_args);
	if (err) {
		se_print("CBC Decrypt: ret:0x%x ---> TEST FAILED\n", err);
		return err;
	}

	for (i = 0; i < 16; i++) {
		if ((i % 10) == 0)
			printf("\n");
		printf("%02x:%02x ", cipher_args.output[i], hash_data[i]);
	}

	if (memcmp(hash_data, cipher_args.output, sizeof(hash_data)) != 0)
		se_print("Decrypted data doesn't match encrypted data [FAIL]\n");

	return err;
}

she_err_t do_she_cipher_test(she_hdl_t cipher_handle)
{
	she_err_t err;

	err = she_cbc_test(cipher_handle);
	if (err)
		se_print("CBC CIPHER TEST ---> FAILED\n");
	else
		se_print("CBC CIPHER TEST ---> PASSED\n");

	err = she_ecb_test(cipher_handle);
	if (err)
		se_print("ECB CIPHER TEST ---> FAILED\n");
	else
		se_print("ECB CIPHER TEST ---> PASSED\n");

	return err;
}
