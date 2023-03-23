/*
 * Copyright 2022-2023 NXP
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

#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "hsm_api.h"
#include "nvm.h"

#define LINE_SIZE		12
#define LAST_IDX_IN_A_LINE	(LINE_SIZE - 1)
#define LOG_LEVEL		0

static void test_status(uint8_t *input, uint8_t *output, int len, char *result_str)
{
	int j;

	printf("Test Output for %s:\n", result_str);
#if (LOG_LEVEL > 0)
	for (j = 0; j < len; j++) {
		printf("0x%02x, ", output[j]);
		if (j % LINE_SIZE == 15)
			printf("\n");
	}
#endif
	if (memcmp(output, input, len) == 0) {
		printf("Result --> SUCCESS\n");
	} else {
		printf("Result --> FAILURE\n");
	}
}
//extern void hash_test(hsm_hdl_t hash_sess);
static uint8_t  hash_test_message[300] = {
	/* Note that the first 32 Bytes are the "Z" value
	 * that can be retrieved with hsm_sm2_get_z()
	 */
	0xB2, 0xE1, 0x4C, 0x5C, 0x79, 0xC6, 0xDF, 0x5B, 0x85, 0xF4, 0xFE, 0x7E,
	0xD8, 0xDB, 0x7A, 0x26,	0x2B, 0x9D, 0xA7, 0xE0, 0x7C, 0xCB, 0x0E, 0xA9,
	0xF4, 0x74, 0x7B, 0x8C, 0xCD, 0xA8, 0xA4, 0xF3, 0x6D, 0x65, 0x73, 0x73,
	0x61, 0x67, 0x65, 0x20, 0xB2, 0xE1, 0x4C, 0x5C, 0x79, 0xC6, 0xDF, 0x5B,
	0x85, 0xF4, 0xFE, 0x7E, 0xD8, 0xDB, 0x7A, 0x26, 0x2B, 0x9D, 0xA7, 0xE0,
	0x7C, 0xCB, 0x0E, 0xA9,	0xF4, 0x74, 0x7B, 0x8C, 0xCD, 0xA8, 0xA4, 0xF3,
	0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20,	0xB2, 0xE1, 0x4C, 0x5C,
	0x79, 0xC6, 0xDF, 0x5B, 0x85, 0xF4, 0xFE, 0x7E, 0xD8, 0xDB, 0x7A, 0x26,
	0x2B, 0x9D, 0xA7, 0xE0, 0x7C, 0xCB, 0x0E, 0xA9, 0xF4, 0x74, 0x7B, 0x8C,
	0xCD, 0xA8, 0xA4, 0xF3,	0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20,
	0xB2, 0xE1, 0x4C, 0x5C, 0x79, 0xC6, 0xDF, 0x5B, 0x85, 0xF4, 0xFE, 0x7E,
	0xD8, 0xDB, 0x7A, 0x26, 0x2B, 0x9D, 0xA7, 0xE0, 0x7C, 0xCB, 0x0E, 0xA9,
	0xF4, 0x74, 0x7B, 0x8C, 0xCD, 0xA8, 0xA4, 0xF3, 0x6D, 0x65, 0x73, 0x73,
	0x61, 0x67, 0x65, 0x20,	0xB2, 0xE1, 0x4C, 0x5C, 0x79, 0xC6, 0xDF, 0x5B,
	0x85, 0xF4, 0xFE, 0x7E, 0xD8, 0xDB, 0x7A, 0x26,	0x2B, 0x9D, 0xA7, 0xE0,
	0x7C, 0xCB, 0x0E, 0xA9, 0xF4, 0x74, 0x7B, 0x8C, 0xCD, 0xA8, 0xA4, 0xF3,
	0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0xB2, 0xE1, 0x4C, 0x5C,
	0x79, 0xC6, 0xDF, 0x5B,	0x85, 0xF4, 0xFE, 0x7E, 0xD8, 0xDB, 0x7A, 0x26,
	0x2B, 0x9D, 0xA7, 0xE0, 0x7C, 0xCB, 0x0E, 0xA9,	0xF4, 0x74, 0x7B, 0x8C,
	0xCD, 0xA8, 0xA4, 0xF3, 0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20,
	0xB2, 0xE1, 0x4C, 0x5C, 0x79, 0xC6, 0xDF, 0x5B, 0x85, 0xF4, 0xFE, 0x7E,
	0xD8, 0xDB, 0x7A, 0x26,	0x2B, 0x9D, 0xA7, 0xE0, 0x7C, 0xCB, 0x0E, 0xA9,
	0xF4, 0x74, 0x7B, 0x8C, 0xCD, 0xA8, 0xA4, 0xF3,	0x6D, 0x65, 0x73, 0x73,
	0x61, 0x67, 0x65, 0x20, 0xB2, 0xE1, 0x4C, 0x5C, 0x79, 0xC6, 0xDF, 0x5B,
	0x85, 0xF4, 0xFE, 0x7E, 0xD8, 0xDB, 0x7A, 0x26, 0x2B, 0x9D, 0xA7, 0xE0,
};

uint8_t hash_work_area[128] = {0};

static uint8_t SHA224_HASH[28] = {
	0x55, 0x4d, 0x5e, 0xed, 0x37, 0x31, 0x6f, 0xca, 0xd7, 0x08, 0x72, 0x54,
	0x4e, 0x05, 0x8c, 0xd4, 0xfc, 0x9e, 0x1c, 0x68, 0xe3, 0xda, 0x18, 0x29,
	0x44, 0x39, 0xb4, 0xaa,
};

static uint8_t SHA256_HASH[32] = {
	0x1b, 0x6a, 0x99, 0xe1, 0x5a, 0x4a, 0x57, 0x86, 0x7d, 0x8a, 0x8f, 0xb1,
	0x43, 0xf7, 0xfc, 0x7d,	0xdd, 0x0a, 0x5a, 0xf2, 0x45, 0x5f, 0xfc, 0xba,
	0x0b, 0x77, 0xf7, 0x92, 0xa0, 0xf1, 0xbf, 0x20,
};

static uint8_t SHA384_HASH[48] = {
	0xa9, 0x30, 0xfe, 0x88, 0x38, 0xcb, 0x69, 0xab, 0x44, 0xc2, 0xac, 0x6d,
	0xb3, 0xb5, 0x28, 0xf3, 0xe9, 0xad, 0x3c, 0x38, 0xaa, 0xc3, 0xb8, 0xe5,
	0xe0, 0x1f, 0xf9, 0x28, 0x71, 0xfc, 0x09, 0xe9, 0xb2, 0x67, 0x7f, 0x5e,
	0xb2, 0xda, 0x7e, 0x6d, 0x6f, 0x08, 0xe4, 0x52, 0xa4, 0x5f, 0x01, 0x48,
};

static uint8_t SHA512_HASH[64] = {
	0xee, 0x29, 0x10, 0x30, 0xb7, 0xe3, 0xf0, 0x70, 0x4c, 0x8b, 0x7c, 0xe5,
	0x1c, 0x99, 0x46, 0x1c, 0xea, 0xc3, 0xf9, 0xba, 0xb5, 0xc3, 0x8f, 0x3c,
	0x8c, 0xc8, 0x59, 0x40, 0x20, 0x68, 0x3d, 0x1e, 0xb5, 0x3c, 0xdf, 0x0a,
	0x08, 0xed, 0xed, 0x01, 0x70, 0x12, 0xe2, 0xb0, 0x5a, 0xe9, 0xa3, 0x5e,
	0x41, 0xc4, 0xe7, 0x6e, 0x8c, 0x11, 0x54, 0x35, 0xba, 0x36, 0x53, 0x54,
	0xeb, 0x62, 0xd0, 0x9f,
};

static uint8_t SM3_HASH[32] = {
	0x52, 0x1d, 0xa1, 0x93, 0x21, 0xcb, 0x3a, 0xfc, 0xb5, 0x13, 0x25, 0x45,
	0x7f, 0x8f, 0x15, 0x89,	0xdc, 0x60, 0xfa, 0xf0, 0x87, 0xf2, 0xcf, 0x8f,
	0xf3, 0xe2, 0x8d, 0x8b, 0xde, 0x28, 0x97, 0x8e,
};

void hash_test(hsm_hdl_t hash_sess)
{
#ifndef PSA_COMPLIANT
	open_svc_hash_args_t hash_srv_args;
	hsm_hdl_t hash_serv;
#endif
	op_hash_one_go_args_t hash_args;
	hsm_err_t err;
	int hash_size;
	int j;

	printf("\n---------------------------------------------------\n");
	printf("HASH Test\n");
	printf("---------------------------------------------------\n");
#ifndef PSA_COMPLIANT
	err = hsm_open_hash_service(hash_sess, &hash_srv_args, &hash_serv);
	printf("err: 0x%x hsm_open_hash_service hdl: 0x%08x\n", err, hash_serv);
#endif
	memset(hash_work_area, 0, sizeof(hash_work_area));
	hash_args.input = hash_test_message;
	hash_args.output = hash_work_area;
	hash_args.input_size = sizeof(hash_test_message);
	hash_args.algo = HSM_HASH_ALGO_SHA_224;
	hash_size = 28;
	hash_args.output_size = hash_size;

#ifndef PSA_COMPLIANT
	err = hsm_hash_one_go(hash_serv, &hash_args);
#else
	err = hsm_hash_one_go(hash_sess, &hash_args);
#endif
	printf("err: 0x%x hsm_hash_one_go hash size: 0x%08x\n", err, hash_args.output_size);

	test_status(SHA224_HASH, hash_work_area, sizeof(SHA224_HASH), "HSM_HASH_ALGO_SHA_224");

	memset(hash_work_area, 0, sizeof(hash_work_area));
	hash_args.input = hash_test_message;
	hash_args.output = hash_work_area;
	hash_args.input_size = sizeof(hash_test_message);
	hash_args.algo = HSM_HASH_ALGO_SHA_256;
	hash_size = 32;
	hash_args.output_size = hash_size;

#ifndef PSA_COMPLIANT
	err = hsm_hash_one_go(hash_serv, &hash_args);
#else
	err = hsm_hash_one_go(hash_sess, &hash_args);
#endif
	printf("err: 0x%x hsm_hash_one_go hash size: 0x%08x\n", err, hash_args.output_size);

	test_status(SHA256_HASH, hash_work_area, sizeof(SHA256_HASH), "HSM_HASH_ALGO_SHA_256");

	memset(hash_work_area, 0, sizeof(hash_work_area));
	hash_args.input = hash_test_message;
	hash_args.output = hash_work_area;
	hash_args.input_size = sizeof(hash_test_message);
	hash_args.algo = HSM_HASH_ALGO_SHA_384;
	hash_size = 48;
	hash_args.output_size = hash_size;

#ifndef PSA_COMPLIANT
	err = hsm_hash_one_go(hash_serv, &hash_args);
#else
	err = hsm_hash_one_go(hash_sess, &hash_args);
#endif
	printf("err: 0x%x hsm_hash_one_go hash size: 0x%08x\n", err, hash_args.output_size);

	test_status(SHA384_HASH, hash_work_area, sizeof(SHA384_HASH), "HSM_HASH_ALGO_SHA_384");

	memset(hash_work_area, 0, sizeof(hash_work_area));
	hash_args.input = hash_test_message;
	hash_args.output = hash_work_area;
	hash_args.input_size = sizeof(hash_test_message);
	hash_args.algo = HSM_HASH_ALGO_SHA_512;
	hash_size = 64;
	hash_args.output_size = hash_size;

#ifndef PSA_COMPLIANT
	err = hsm_hash_one_go(hash_serv, &hash_args);
#else
	err = hsm_hash_one_go(hash_sess, &hash_args);
#endif
	printf("err: 0x%x hsm_hash_one_go hash size: 0x%08x\n", err, hash_args.output_size);

	test_status(SHA512_HASH, hash_work_area, sizeof(SHA512_HASH), "HSM_HASH_ALGO_SHA_512");

#if PLAT_ELE_FEAT_NOT_SUPPORTED
	memset(hash_work_area, 0, sizeof(hash_work_area));
	hash_args.input = hash_test_message;
	hash_args.output = hash_work_area;
	hash_args.input_size = sizeof(hash_test_message);
	hash_args.algo = HSM_HASH_ALGO_SM3_256;
	hash_size = 32;
	hash_args.output_size = hash_size;

	err = hsm_hash_one_go(hash_serv, &hash_args);
	printf("err: 0x%x hsm_hash_one_go hdl: 0x%08x\n", err, hash_serv);
	test_status(SM3_HASH, hash_work_area, sizeof(SM3_HASH), "HSM_HASH_ALGO_SM3_256");
#endif

#ifndef PSA_COMPLIANT
	err = hsm_close_hash_service(hash_serv);
	printf("err: 0x%x hsm_close_hash_service hdl: 0x%08x\n", err, hash_serv);
#endif

	printf("---------------------------------------------------\n\n");
}

// hash_sess is hsm session handle
hsm_err_t do_hash_test(hsm_hdl_t hash_sess)
{
	op_hash_one_go_args_t hash_args = {0};
	hsm_err_t err;
	int hash_size;
	hsm_hash_algo_t alg;

	memset(hash_work_area, 0, sizeof(hash_work_area));

	for (alg = HSM_HASH_ALGO_SHA_224; alg <= HSM_HASH_ALGO_SHA_512; alg++) {
		hash_args.algo = alg;
		if (hash_args.algo == HSM_HASH_ALGO_SHA_256)
			hash_size = 32;
		else if (hash_args.algo == HSM_HASH_ALGO_SHA_224)
			hash_size = 28;
		else if (hash_args.algo == HSM_HASH_ALGO_SHA_384)
			hash_size = 48;
		else if (hash_args.algo == HSM_HASH_ALGO_SHA_512)
			hash_size = 64;

		hash_args.output_size = hash_size;
		hash_args.output = hash_work_area;
		hash_args.input = hash_test_message;
		hash_args.input_size = sizeof(hash_test_message);

#ifdef PSA_COMPLIANT
		hash_args.svc_flags = HSM_HASH_FLAG_ONE_SHOT;
#else
		hash_args.svc_flags = 0x0;
#endif
		err = hsm_do_hash(hash_sess, &hash_args);

		if (hash_args.algo == HSM_HASH_ALGO_SHA_256)
			test_status(SHA256_HASH, hash_work_area,
				    sizeof(SHA256_HASH), "HSM_HASH_ALGO_SHA_256");
		else if (hash_args.algo == HSM_HASH_ALGO_SHA_224)
			test_status(SHA224_HASH, hash_work_area,
				    sizeof(SHA224_HASH), "HSM_HASH_ALGO_SHA_224");
		else if (hash_args.algo == HSM_HASH_ALGO_SHA_384)
			test_status(SHA384_HASH, hash_work_area,
				    sizeof(SHA384_HASH), "HSM_HASH_ALGO_SHA_384");
		else if (hash_args.algo == HSM_HASH_ALGO_SHA_512)
			test_status(SHA512_HASH, hash_work_area,
				    sizeof(SHA512_HASH), "HSM_HASH_ALGO_SHA_512");
	}

#if PLAT_ELE_FEAT_NOT_SUPPORTED
	memset(hash_work_area, 0, sizeof(hash_work_area));
	hash_args.algo = HSM_HASH_ALGO_SM3_256;
	hash_size = 32;
	hash_args.output_size = hash_size;

	err = hsm_do_hash(hash_sess, &hash_args);
	test_status(SM3_HASH, hash_work_area, sizeof(SM3_HASH), "HSM_HASH_ALGO_SM3_256");
#endif
	printf("\n-----------hash one shot operation end-------------\n");
	return err;
}

// hash_sess is hsm session handle
hsm_err_t do_hash_stream_test(hsm_hdl_t hash_sess)
{
	op_hash_one_go_args_t hash_args = {0};
	hsm_err_t err;
	int hash_size, i, j;
	hsm_hash_algo_t alg;
	uint8_t hash_temp_input1[75];
	uint8_t hash_temp_input2[75];
	uint8_t hash_temp_input3[75];
	uint8_t hash_temp_input4[75];
	uint8_t ctx_input[256];

	memset(hash_temp_input1, 0, sizeof(hash_temp_input1));
	memset(hash_temp_input2, 0, sizeof(hash_temp_input2));
	memset(hash_temp_input3, 0, sizeof(hash_temp_input3));
	memset(hash_temp_input4, 0, sizeof(hash_temp_input4));

	memset(hash_work_area, 0, sizeof(hash_work_area));

	for (alg = HSM_HASH_ALGO_SHA_224; alg <= HSM_HASH_ALGO_SHA_512; alg++) {
		hash_args.algo = alg;
		if (hash_args.algo == HSM_HASH_ALGO_SHA_256)
			hash_size = 32;
		else if (hash_args.algo == HSM_HASH_ALGO_SHA_224)
			hash_size = 28;
		else if (hash_args.algo == HSM_HASH_ALGO_SHA_384)
			hash_size = 48;
		else if (hash_args.algo == HSM_HASH_ALGO_SHA_512)
			hash_size = 64;

		hash_args.svc_flags = HSM_HASH_FLAG_GET_CONTEXT;
		err = hsm_do_hash(hash_sess, &hash_args);

		for (i = 0; i < 75; i++)
			hash_temp_input1[i] = hash_test_message[i];

		memset(ctx_input, 0, sizeof(ctx_input));
#ifdef PSA_COMPLIANT
		hash_args.ctx = ctx_input;
		hash_args.ctx_size = hash_args.context_size;
#endif
		hash_args.input = hash_temp_input1;
		hash_args.input_size = sizeof(hash_temp_input1);
		hash_args.svc_flags = HSM_HASH_FLAG_INIT;

		err = hsm_do_hash(hash_sess, &hash_args);

		for (i, j = 0; i < 150; i++, j++)
			hash_temp_input2[j] = hash_test_message[i];

		hash_args.input = hash_temp_input2;
		hash_args.input_size = sizeof(hash_temp_input2);
		hash_args.svc_flags = HSM_HASH_FLAG_UPDATE;

		err = hsm_do_hash(hash_sess, &hash_args);

		for (i, j = 0; i < 225; i++, j++)
			hash_temp_input3[j] = hash_test_message[i];

		hash_args.input = hash_temp_input3;
		hash_args.input_size = sizeof(hash_temp_input3);
		hash_args.svc_flags = HSM_HASH_FLAG_UPDATE;

		err = hsm_do_hash(hash_sess, &hash_args);

		for (i, j = 0; i < 300; i++, j++)
			hash_temp_input4[j] = hash_test_message[i];

		hash_args.output_size = hash_size;
		hash_args.output = hash_work_area;
		hash_args.input = hash_temp_input4;
		hash_args.input_size = sizeof(hash_temp_input4);
		hash_args.svc_flags = HSM_HASH_FLAG_FINAL;

		err = hsm_do_hash(hash_sess, &hash_args);

		if (hash_args.algo == HSM_HASH_ALGO_SHA_256)
			test_status(SHA256_HASH, hash_work_area,
				    sizeof(SHA256_HASH), "HSM_HASH_ALGO_SHA_256");
		else if (hash_args.algo == HSM_HASH_ALGO_SHA_224)
			test_status(SHA224_HASH, hash_work_area,
				    sizeof(SHA224_HASH), "HSM_HASH_ALGO_SHA_224");
		else if (hash_args.algo == HSM_HASH_ALGO_SHA_384)
			test_status(SHA384_HASH, hash_work_area,
				    sizeof(SHA384_HASH), "HSM_HASH_ALGO_SHA_384");
		else if (hash_args.algo == HSM_HASH_ALGO_SHA_512)
			test_status(SHA512_HASH, hash_work_area,
				    sizeof(SHA512_HASH), "HSM_HASH_ALGO_SHA_512");
	}

	printf("\n-----------hash stream operation end---------------\n");
	return err;
}
