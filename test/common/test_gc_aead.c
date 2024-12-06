// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#include <stdio.h>

#include "internal/hsm_key.h"

#include "hsm_api.h"

#if MT_SAB_GC_AEAD
uint8_t in_data[16] = {
	0x01, 0x9C, 0x8D, 0x87, 0x35, 0x3A, 0xFB, 0x84,
	0x18, 0x5B, 0x6D, 0x42, 0xC4, 0xAB, 0x19, 0xAC};

uint8_t nonce_data[12] = {
	0x62, 0x83, 0x7F, 0xCC, 0xCC, 0x3C,
	0x3A, 0x6C, 0x22, 0xBE, 0xF5, 0x46 };

uint8_t aad_data[16] = {
	0x18, 0x0C, 0x39, 0x33, 0xC1, 0x15, 0x36, 0xCE,
	0x1D, 0xA9, 0xA5, 0xAE, 0x62, 0xCA, 0xC1, 0x88 };

uint8_t key_id[16] = {
	0x5D, 0xED, 0x4C, 0xA2, 0x34, 0xBC, 0x56, 0xCC,
	0xAD, 0x75, 0x57, 0xE0, 0x8F, 0xCB, 0x36, 0x4D };

uint8_t tag_data[16] = {
	0xAF, 0x4A, 0xAB, 0x3A, 0xA0, 0xE8, 0xE1, 0x58,
	0x1E, 0x55, 0xF7, 0x77, 0x09, 0x28, 0x4F, 0x18 };

uint8_t ciphered[16] = {0};
uint8_t deciphered[16] = {0};

hsm_err_t gc_aead_test(hsm_hdl_t session_hdl)
{
	op_gc_aead_args_t gc_aead_args = {0};
	hsm_err_t hsmret = HSM_GENERAL_ERROR;

	printf("---------------------------------------------------\n");
	printf("Generic Crypto: Symmetric AEAD Test\n");
	printf("---------------------------------------------------\n");

	gc_aead_args.plain_key_buff = key_id;
	gc_aead_args.plain_key_buff_sz = sizeof(key_id);
	gc_aead_args.nonce_buff = nonce_data;
	gc_aead_args.nonce_sz = sizeof(nonce_data);
	gc_aead_args.op_mode = HSM_GC_AEAD_OP_MODE_ENCRYPT;
	gc_aead_args.algorithm = HSM_GC_AEAD_ALGO_AES_GCM;
	gc_aead_args.in_data_buff = in_data;
	gc_aead_args.out_data_buff = ciphered;
	gc_aead_args.in_data_buff_sz = sizeof(in_data);
	gc_aead_args.aad_buff = aad_data;
	gc_aead_args.aad_sz = sizeof(aad_data);
	gc_aead_args.tag_buff = tag_data;
	gc_aead_args.tag_sz = sizeof(tag_data);

	hsmret = hsm_gc_aead(session_hdl, &gc_aead_args);
	if (hsmret)
		printf("hsm_gc_aead ret:0x%x\n", hsmret);

	gc_aead_args.op_mode = HSM_GC_AEAD_OP_MODE_DECRYPT;
	gc_aead_args.in_data_buff = ciphered;
	gc_aead_args.out_data_buff = deciphered;
	gc_aead_args.in_data_buff_sz = sizeof(ciphered);
	hsmret = hsm_gc_aead(session_hdl, &gc_aead_args);
	if (hsmret)
		printf("hsm_gc_aead ret:0x%x\n", hsmret);

	if (memcmp(in_data, deciphered, sizeof(in_data)) == 0)
		printf("\nDecrypted data matches encrypted data [PASS]\n");
	else
		printf("\nDecrypted data doesn't match encrypted data [FAIL]\n");

	printf("\n---------------------------------------------------\n");
	printf("Generic Crypto: Symmetric AEAD Test Complete\n");
	printf("---------------------------------------------------\n");

	return hsmret;
}
#endif
