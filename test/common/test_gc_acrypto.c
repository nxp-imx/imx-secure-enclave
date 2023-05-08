// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <stdio.h>

#include "hsm_api.h"
#include "internal/hsm_gc_acrypto.h"
#include "internal/hsm_key.h"

#ifdef MT_SAB_GC_ACRYPTO

//plaintext or message or digest
uint8_t plaintext[32] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
	};

//ciphertext
uint8_t ciphertext[256];

// Buffer to verify Decrypt operation
uint8_t known_ciphertext[256] = {
	0x9e, 0x38, 0x1a, 0x4f, 0xfa, 0x58, 0x64, 0x1c,
	0x1e, 0xec, 0x96, 0x22, 0x23, 0xfe, 0xea, 0x61,
	0x5a, 0xfc, 0xb6, 0x7e, 0xe7, 0x72, 0xbb, 0x59,
	0x5e, 0xd2, 0x67, 0x63, 0x93, 0x0e, 0x11, 0x65,
	0xf4, 0xbe, 0xd2, 0xc1, 0x2b, 0x44, 0xcd, 0x1d,
	0x60, 0x10, 0x89, 0x92, 0xe8, 0xed, 0xe3, 0xaa,
	0xea, 0x85, 0xd3, 0xef, 0x0c, 0xcc, 0xc1, 0xe5,
	0x28, 0xe0, 0x2e, 0xaf, 0x81, 0x16, 0xbe, 0x99,
	0xaa, 0xde, 0x5b, 0x86, 0x10, 0xe7, 0x47, 0x21,
	0xd6, 0xe6, 0x41, 0xbf, 0x96, 0x97, 0xa9, 0xde,
	0xd5, 0xa8, 0x94, 0x44, 0xd9, 0xf6, 0x96, 0x16,
	0x48, 0xc5, 0x92, 0xc6, 0x3a, 0xf0, 0xc0, 0x6f,
	0xcf, 0xa2, 0xf6, 0x63, 0x13, 0xd4, 0x6a, 0xa6,
	0xf7, 0x0d, 0x4a, 0xde, 0xaa, 0xae, 0x56, 0x15,
	0xc8, 0x2c, 0x4d, 0x2c, 0x4d, 0x2d, 0x46, 0x5c,
	0xa0, 0xf2, 0x7c, 0x27, 0x98, 0xb9, 0x83, 0xb9,
	0x72, 0x41, 0x17, 0x81, 0xfa, 0xb9, 0x7c, 0x3c,
	0x90, 0xcd, 0x66, 0x4e, 0xd6, 0x30, 0xcf, 0x96,
	0x8a, 0x86, 0xd9, 0x04, 0x46, 0xde, 0xe8, 0xf1,
	0xc4, 0xca, 0x67, 0x08, 0xb3, 0x89, 0xae, 0xe9,
	0xa4, 0xba, 0xf0, 0xa3, 0xbe, 0x69, 0xbb, 0x5b,
	0x2e, 0x09, 0x63, 0xd1, 0xa0, 0x43, 0x8c, 0x9f,
	0xfa, 0xa3, 0x86, 0xf6, 0x6a, 0x71, 0x80, 0xfc,
	0xbf, 0xf4, 0x8c, 0xe9, 0xdc, 0xaa, 0xad, 0xc9,
	0x7d, 0x06, 0x9b, 0x9a, 0xc8, 0x1b, 0x71, 0x99,
	0xac, 0xa8, 0xe9, 0x68, 0x0d, 0x57, 0x09, 0xa4,
	0x8e, 0x43, 0x1d, 0xa6, 0x1f, 0xf9, 0xd7, 0x19,
	0xdb, 0x91, 0xd0, 0xb2, 0x73, 0x46, 0xc8, 0x18,
	0x64, 0xa3, 0x3e, 0xb8, 0xfb, 0x75, 0xd4, 0x4d,
	0xc1, 0x4c, 0xbd, 0x53, 0x6b, 0xde, 0x18, 0x30,
	0x09, 0x0b, 0xb0, 0x01, 0x7e, 0x53, 0x13, 0xb5,
	0x56, 0x02, 0x87, 0x7c, 0x36, 0x68, 0xd8, 0xf3,
	};

uint8_t deciphered_text[32];

//signature
uint8_t signature[256];

uint8_t known_signature[256] = {
	0x99, 0xfe, 0xbe, 0xb6, 0x1c, 0x48, 0x4b, 0xf8,
	0x88, 0xfb, 0x83, 0xc1, 0x00, 0x02, 0x71, 0x29,
	0x52, 0x6d, 0x24, 0x77, 0x4d, 0x71, 0x6f, 0x02,
	0x8a, 0x25, 0x8b, 0xef, 0xa4, 0xc1, 0x9d, 0x0f,
	0x67, 0x6e, 0xd4, 0x9a, 0x5a, 0x64, 0xa5, 0xf8,
	0x02, 0x63, 0xcc, 0xc3, 0xbc, 0x0c, 0xc4, 0x3f,
	0xde, 0xe7, 0x2d, 0x06, 0x66, 0x77, 0x04, 0x93,
	0x44, 0x9b, 0x62, 0x3c, 0x68, 0x73, 0x34, 0xba,
	0x21, 0xc7, 0xe7, 0x87, 0x65, 0x80, 0x04, 0x23,
	0xae, 0x01, 0xf1, 0x01, 0x9f, 0x08, 0xd8, 0x94,
	0x8a, 0x8b, 0xae, 0x0c, 0xe7, 0x47, 0x12, 0xfb,
	0xc9, 0x68, 0xa3, 0x07, 0x9d, 0xa5, 0xa0, 0xb6,
	0x37, 0xaa, 0x24, 0xce, 0x2c, 0x5a, 0xdc, 0xdd,
	0xcc, 0x3c, 0x3d, 0x13, 0xf5, 0x0c, 0x88, 0x94,
	0xe8, 0xcd, 0xf3, 0xea, 0xac, 0xfa, 0x0d, 0xc6,
	0x8a, 0x10, 0xed, 0x10, 0xe1, 0xf3, 0xe8, 0x1d,
	0x94, 0x0f, 0x72, 0xbd, 0x76, 0xa9, 0x6b, 0x42,
	0xe8, 0x6e, 0xdf, 0x71, 0x8b, 0x2d, 0xd6, 0x9b,
	0x69, 0x8a, 0xcf, 0x05, 0x15, 0x53, 0x16, 0x87,
	0x0b, 0x0d, 0xd3, 0x79, 0x43, 0x50, 0xd2, 0xc5,
	0xcf, 0xda, 0x7c, 0xa7, 0x81, 0x6f, 0x9e, 0x28,
	0xe9, 0xeb, 0xf0, 0x33, 0x67, 0x50, 0xd5, 0x25,
	0xf4, 0x45, 0x82, 0xf2, 0x79, 0xb9, 0xbc, 0x16,
	0x1a, 0x92, 0xec, 0x32, 0x2a, 0x85, 0xf8, 0x67,
	0x02, 0x8c, 0x78, 0x1c, 0x20, 0x3f, 0x4a, 0x45,
	0xab, 0x76, 0x8f, 0x55, 0x30, 0x13, 0xa6, 0x10,
	0xa7, 0xf1, 0x21, 0xed, 0x47, 0x4f, 0x77, 0xf1,
	0xf4, 0x23, 0x62, 0x31, 0x9d, 0x5f, 0x4c, 0x2c,
	0xd1, 0xd3, 0xaf, 0xe3, 0x95, 0x91, 0x3f, 0xba,
	0x5a, 0x9b, 0xf6, 0xd9, 0xf0, 0x7c, 0x2d, 0x94,
	0x50, 0xa8, 0xea, 0x73, 0xd4, 0x07, 0xd1, 0x9a,
	0xa2, 0x19, 0x7c, 0x9f, 0x19, 0xdd, 0x96, 0x6b,
	};

uint8_t modulus_buff[256] = {
	0xd9, 0xa4, 0x90, 0x94, 0xad, 0xb2, 0x53, 0xe7,
	0xf9, 0x5e, 0x1d, 0x50, 0x00, 0x30, 0x9a, 0x39,
	0xe7, 0x53, 0xbe, 0xa8, 0x54, 0x68, 0x26, 0x1c,
	0x51, 0x34, 0xa9, 0x60, 0x91, 0xb6, 0xeb, 0x72,
	0x8d, 0xa3, 0xc1, 0x23, 0x84, 0xad, 0xad, 0x36,
	0xa9, 0x9e, 0x18, 0x36, 0x36, 0xc0, 0x9d, 0xc7,
	0x4d, 0x79, 0x34, 0xff, 0x86, 0x82, 0x8d, 0x38,
	0xf1, 0xc8, 0xf2, 0x6b, 0xa9, 0xb3, 0xb8, 0xf7,
	0xa5, 0xb9, 0xf6, 0xf6, 0x73, 0xbe, 0x51, 0x31,
	0xd0, 0x3c, 0x70, 0x6e, 0xfa, 0x88, 0xb0, 0x78,
	0xcd, 0x02, 0x25, 0x84, 0x13, 0x8c, 0x5e, 0xa3,
	0x8f, 0x5d, 0x90, 0xac, 0x1a, 0x35, 0x63, 0x05,
	0x9a, 0xa1, 0x51, 0xfa, 0x23, 0xec, 0xf4, 0x99,
	0x93, 0x39, 0xb0, 0x83, 0x98, 0x5b, 0x0f, 0xf0,
	0xcd, 0x7b, 0xdc, 0x22, 0xe2, 0x04, 0x69, 0x0b,
	0x27, 0xa7, 0x91, 0xe7, 0x7b, 0x0e, 0x0f, 0x72,
	0xc4, 0x87, 0xe1, 0x49, 0x60, 0x60, 0x7e, 0x95,
	0x14, 0x82, 0x62, 0x44, 0xbe, 0xfb, 0xe4, 0x38,
	0xb7, 0xf3, 0x8d, 0xcd, 0x2d, 0xdc, 0x54, 0x22,
	0x39, 0x8a, 0x9c, 0xf3, 0x99, 0x1e, 0x67, 0x43,
	0xe6, 0x18, 0xf3, 0x6a, 0x59, 0x57, 0xbf, 0xf3,
	0x67, 0x46, 0x70, 0x47, 0xdc, 0x9f, 0x7c, 0xa9,
	0x50, 0x5a, 0x68, 0xd4, 0x6a, 0xb5, 0xb3, 0xcd,
	0xfe, 0xcf, 0xb7, 0x1d, 0xf0, 0xf1, 0x32, 0x10,
	0x70, 0x18, 0x92, 0xdb, 0x2a, 0x55, 0x44, 0x34,
	0x79, 0x2e, 0x68, 0xa4, 0xf9, 0xc2, 0x42, 0xf8,
	0xd2, 0xef, 0x79, 0x37, 0x1c, 0x8c, 0x00, 0x1a,
	0xc9, 0x5e, 0x7b, 0xcb, 0xd7, 0x68, 0x14, 0x3b,
	0x62, 0x9f, 0x29, 0xb3, 0x0c, 0xd5, 0x46, 0x93,
	0x82, 0xc4, 0x1b, 0xbd, 0xbc, 0x80, 0xdb, 0x5f,
	0x22, 0x67, 0x8a, 0x75, 0x8c, 0xea, 0xfd, 0x28,
	0x8e, 0xbc, 0x0b, 0xc9, 0xe5, 0xc9, 0x8d, 0xbd,
	};

uint8_t priv_exp_buff[256] = {
	0x4e, 0xdf, 0x6e, 0x0d, 0x28, 0xaa, 0x93, 0xaf,
	0x91, 0x65, 0x0f, 0xc7, 0x1f, 0xab, 0xda, 0x12,
	0x78, 0xb9, 0xd2, 0x4f, 0x22, 0x5e, 0xae, 0x05,
	0xe0, 0x4d, 0x95, 0xf9, 0x4f, 0x52, 0x26, 0xf0,
	0x9e, 0xc9, 0x2e, 0x4e, 0xcd, 0x26, 0xfe, 0x69,
	0x80, 0xcf, 0x54, 0xcd, 0xd8, 0x0e, 0xa7, 0x84,
	0x5e, 0x72, 0xbe, 0x4f, 0x8a, 0x28, 0x59, 0x28,
	0xbd, 0xf3, 0xa3, 0x97, 0xfd, 0xb4, 0x62, 0x3b,
	0x98, 0x11, 0x49, 0xc1, 0xd2, 0xae, 0x8a, 0xc0,
	0xe6, 0xf2, 0xdc, 0x71, 0x6d, 0xa6, 0x9c, 0x6a,
	0xe5, 0xde, 0xab, 0x34, 0x0a, 0x90, 0x40, 0xfc,
	0xb6, 0xf2, 0xfa, 0x37, 0x18, 0xee, 0x5a, 0x1a,
	0xa5, 0x7f, 0xc4, 0xe3, 0x7f, 0x32, 0x00, 0x63,
	0x29, 0x16, 0x1a, 0xe4, 0xee, 0xdb, 0x59, 0xb5,
	0xb5, 0x04, 0xd7, 0x2b, 0x4a, 0xe9, 0x74, 0xfe,
	0xfa, 0xef, 0x3f, 0xc3, 0xc5, 0xe7, 0xa4, 0x4a,
	0x11, 0xbe, 0x71, 0x23, 0xf4, 0xce, 0xc7, 0x9c,
	0x76, 0x25, 0xf4, 0xe0, 0x9f, 0x35, 0x1b, 0x9b,
	0xc1, 0x39, 0x94, 0x09, 0x0d, 0x8e, 0x48, 0xf4,
	0xca, 0x47, 0xe2, 0x68, 0x20, 0xe3, 0x61, 0xca,
	0x18, 0x71, 0x0c, 0xde, 0x1a, 0xd1, 0xed, 0xdd,
	0x23, 0x45, 0xbc, 0xd1, 0x04, 0xee, 0x0b, 0xb5,
	0x0e, 0xca, 0x02, 0xa2, 0xc0, 0x9a, 0xb7, 0xed,
	0xb9, 0x9a, 0x3e, 0x6c, 0x5a, 0x28, 0x84, 0x5f,
	0xfd, 0xbd, 0xa9, 0x0e, 0x94, 0x7c, 0x45, 0xe9,
	0x15, 0x5a, 0xc2, 0xc3, 0xbd, 0x5b, 0xf9, 0x50,
	0x58, 0x6b, 0xdb, 0x08, 0x59, 0xf7, 0xa4, 0xa1,
	0x31, 0x8a, 0xba, 0x88, 0xbc, 0xaf, 0x0e, 0xc6,
	0xe7, 0xe0, 0x51, 0x71, 0x6c, 0xa8, 0x3f, 0x61,
	0xe1, 0x56, 0x01, 0x14, 0xa0, 0xc7, 0xc1, 0xda,
	0x60, 0x3b, 0x3f, 0x14, 0x76, 0x33, 0xc1, 0x49,
	0x77, 0xf8, 0x8e, 0x08, 0x86, 0x92, 0x9a, 0xd3,
	};

uint8_t pub_exp_buff[5] = {
	0x1, 0x0, 0x0, 0x0, 0x1
	};

hsm_err_t gc_acrypto_test(hsm_hdl_t session_hdl)
{
	hsm_err_t err = HSM_GENERAL_ERROR;
	op_gc_acrypto_args_t gc_acrypto_args = {0};

	printf("\n------------------------------------------------\n");
	printf("Generic Crypto - Asymmetric Crypto Test:");
	printf("\n------------------------------------------------\n");

	/* RSA ENCRYPT operation with RSA 2048 key */
	memset(ciphertext, 0, sizeof(ciphertext));

	gc_acrypto_args.algorithm = HSM_GC_ACRYPTO_ALGO_RSA_PKCS1_V15_CRYPT;
	gc_acrypto_args.op_mode = HSM_GC_ACRYPTO_OP_MODE_ENCRYPT;
	gc_acrypto_args.flags = 0;
	gc_acrypto_args.bit_key_sz = HSM_KEY_SIZE_RSA_2048;
	gc_acrypto_args.data_buff1 = plaintext;
	gc_acrypto_args.data_buff2 = ciphertext;
	gc_acrypto_args.data_buff1_size = sizeof(plaintext);
	gc_acrypto_args.data_buff2_size = sizeof(ciphertext);
	gc_acrypto_args.key_buff1 = modulus_buff;
	gc_acrypto_args.key_buff2 = pub_exp_buff;
	gc_acrypto_args.key_buff1_size = sizeof(modulus_buff);
	gc_acrypto_args.key_buff2_size = sizeof(pub_exp_buff);

	err = hsm_gc_acrypto(session_hdl, &gc_acrypto_args);
	printf("\nhsm_gc_acrypto (ENCRYPT) ret: 0x%x\n", err);

	/* RSA DECRYPT operation with RSA 2048 key */
	memset(&gc_acrypto_args, 0, sizeof(gc_acrypto_args));
	memset(deciphered_text, 0, sizeof(deciphered_text));

	gc_acrypto_args.algorithm = HSM_GC_ACRYPTO_ALGO_RSA_PKCS1_V15_CRYPT;
	gc_acrypto_args.op_mode = HSM_GC_ACRYPTO_OP_MODE_DECRYPT;
	gc_acrypto_args.flags = 0;
	gc_acrypto_args.bit_key_sz = HSM_KEY_SIZE_RSA_2048;
	gc_acrypto_args.data_buff1 = deciphered_text;
	gc_acrypto_args.data_buff2 = known_ciphertext;
	gc_acrypto_args.data_buff1_size = sizeof(deciphered_text);
	gc_acrypto_args.data_buff2_size = sizeof(known_ciphertext);
	gc_acrypto_args.key_buff1 = modulus_buff;
	gc_acrypto_args.key_buff2 = priv_exp_buff;
	gc_acrypto_args.key_buff1_size = sizeof(modulus_buff);
	gc_acrypto_args.key_buff2_size = sizeof(priv_exp_buff);

	err = hsm_gc_acrypto(session_hdl, &gc_acrypto_args);
	printf("\nhsm_gc_acrypto (DECRYPT) ret: 0x%x\n", err);

	if (memcmp(plaintext, deciphered_text, sizeof(plaintext)) == 0)
		printf("\nDecrypted Text matches the Plaintext [PASS]\n");
	else
		printf("\nDecrypted Text doesn't match the Plaintext [FAIL]\n");

	/* RSA Signature Generation with RSA 2048 key */
	memset(&gc_acrypto_args, 0, sizeof(gc_acrypto_args));
	memset(signature, 0, sizeof(signature));

	gc_acrypto_args.algorithm = HSM_GC_ACRYPTO_ALGO_RSA_PKCS1_V15_SHA256;
	gc_acrypto_args.op_mode = HSM_GC_ACRYPTO_OP_MODE_SIGN_GEN;
	gc_acrypto_args.flags = HSM_OP_GC_ACRYPTO_FLAGS_INPUT_MESSAGE;
	gc_acrypto_args.bit_key_sz = HSM_KEY_SIZE_RSA_2048;
	gc_acrypto_args.data_buff1 = plaintext;
	gc_acrypto_args.data_buff2 = signature;
	gc_acrypto_args.data_buff1_size = sizeof(plaintext);
	gc_acrypto_args.data_buff2_size = sizeof(signature);
	gc_acrypto_args.key_buff1 = modulus_buff;
	gc_acrypto_args.key_buff2 = priv_exp_buff;
	gc_acrypto_args.key_buff1_size = sizeof(modulus_buff);
	gc_acrypto_args.key_buff2_size = sizeof(priv_exp_buff);

	err = hsm_gc_acrypto(session_hdl, &gc_acrypto_args);
	printf("\n\nhsm_gc_acrypto (Signature Generation) ret: 0x%x\n", err);

	if (memcmp(known_signature, signature, sizeof(known_signature)) == 0)
		printf("\nGenerated Signature matches Expected Signature [PASS]\n");
	else
		printf("\nGenerated Signature doesn't match Expected Signature [FAIL]\n");

	/* RSA Signature Verification with RSA 2048 key */
	memset(&gc_acrypto_args, 0, sizeof(gc_acrypto_args));

	gc_acrypto_args.algorithm = HSM_GC_ACRYPTO_ALGO_RSA_PKCS1_V15_SHA256;
	gc_acrypto_args.op_mode = HSM_GC_ACRYPTO_OP_MODE_SIGN_VER;
	gc_acrypto_args.flags = HSM_OP_GC_ACRYPTO_FLAGS_INPUT_MESSAGE;
	gc_acrypto_args.bit_key_sz = HSM_KEY_SIZE_RSA_2048;
	gc_acrypto_args.data_buff1 = plaintext;
	gc_acrypto_args.data_buff2 = known_signature;
	gc_acrypto_args.data_buff1_size = sizeof(plaintext);
	gc_acrypto_args.data_buff2_size = sizeof(known_signature);
	gc_acrypto_args.key_buff1 = modulus_buff;
	gc_acrypto_args.key_buff2 = pub_exp_buff;
	gc_acrypto_args.key_buff1_size = sizeof(modulus_buff);
	gc_acrypto_args.key_buff2_size = sizeof(pub_exp_buff);

	err = hsm_gc_acrypto(session_hdl, &gc_acrypto_args);
	printf("\n\nhsm_gc_acrypto (Signature Verification) ret: 0x%x\n", err);

	if (gc_acrypto_args.verification_status == HSM_GC_ACRYPTO_VERIFICATION_SUCCESS)
		printf("\nSignature Verification [PASS]\n");
	else
		printf("\nSignature Verification [FAIL]\n");

	printf("\n------------------------------------------------\n");
	printf("Test Complete");
	printf("\n------------------------------------------------\n");

	return err;
}

#endif
