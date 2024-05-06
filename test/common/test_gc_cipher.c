// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#include <stdio.h>

#include "internal/hsm_key.h"

#include "hsm_api.h"

#if MT_SAB_GC_CIPHER
uint8_t input_data[32] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F };

uint8_t iv_buff_data[16] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

uint8_t symm_key_id[16] = {
	0x85, 0x61, 0x0d, 0xbc,	0xbe, 0xe1, 0x00, 0x3c,
	0xab, 0xde, 0x05, 0x52,	0x86, 0x2e, 0xa7, 0x62 };

uint8_t ciphered_data[32] = {0};
uint8_t deciphered_data[32] = {0};

hsm_err_t gc_cipher_test(hsm_hdl_t session_hdl)
{
	op_gc_cipher_args_t gc_cipher_args = {0};
	hsm_err_t hsmret = HSM_GENERAL_ERROR;

	printf("---------------------------------------------------\n");
	printf("Generic Crypto: Symmetric CIPHER Test\n");
	printf("---------------------------------------------------\n");

	gc_cipher_args.plain_key_buff = symm_key_id;
	gc_cipher_args.plain_key_buff_sz = sizeof(symm_key_id);
	gc_cipher_args.iv_buff = iv_buff_data;
	gc_cipher_args.iv_buff_sz = sizeof(iv_buff_data);
	gc_cipher_args.algorithm = HSM_GC_CIPHER_OP_MODE_ENCRYPT;
	gc_cipher_args.op_mode = HSM_GC_CIPHER_ALGO_AES_CBC_NOPAD;
	gc_cipher_args.in_data_buff = input_data;
	gc_cipher_args.out_data_buff = ciphered_data;
	gc_cipher_args.in_data_buff_sz = sizeof(input_data);

	hsmret = hsm_gc_cipher(session_hdl, &gc_cipher_args);
	if (hsmret)
		printf("hsm_gc_cipher ret:0x%x\n", hsmret);

	gc_cipher_args.algorithm = HSM_GC_CIPHER_OP_MODE_DECRYPT;
	gc_cipher_args.in_data_buff = ciphered_data;
	gc_cipher_args.out_data_buff = deciphered_data;
	gc_cipher_args.in_data_buff_sz = sizeof(ciphered_data);

	hsmret = hsm_gc_cipher(session_hdl, &gc_cipher_args);
	if (hsmret)
		printf("hsm_gc_cipher ret:0x%x\n", hsmret);

	if (memcmp(input_data, deciphered_data, sizeof(input_data)) == 0)
		printf("\nDecrypted data matches encrypted data [PASS]\n");
	else
		printf("\nDecrypted data doesn't match encrypted data [FAIL]\n");

	printf("\n---------------------------------------------------\n");
	printf("Generic Crypto: Symmetric CIPHER Test Complete\n");
	printf("---------------------------------------------------\n");

	return hsmret;
}
#endif
