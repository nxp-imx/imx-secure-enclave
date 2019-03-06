/*
 * Copyright 2019 NXP
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * o Redistributions of source code must retain the above copyright notice, this list
 *   of conditions and the following disclaimer.
 *
 * o Redistributions in binary form must reproduce the above copyright notice, this
 *   list of conditions and the following disclaimer in the documentation and/or
 *   other materials provided with the distribution.
 *
 * o Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from this
 *   software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "she_api.h"


/*
 * Test patterns.
 */

static uint8_t mac_input_message[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
									0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
									0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11 };

static uint8_t mac_output[SHE_MAC_SIZE]; /*128bits*/

#define MAC_TEST1_INPUT_SIZE 16
static uint8_t mac_output_ref1[] = {0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44, 0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c};

#define MAC_TEST2_INPUT_SIZE 40
static uint8_t mac_output_ref2[] = {0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30, 0x30, 0xca, 0x32, 0x61, 0x14, 0x97, 0xc8, 0x27};

static uint8_t cbc_iv[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
static uint8_t cbc_plaintext[] = {	0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
									0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
									0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
									0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};

static uint8_t cbc_ciphertext[] = {	0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
									0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
									0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
									0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7};


static uint8_t ecb_plaintext[]  = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
static uint8_t ecb_ciphertext[] = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};

#define SHE_TEST_MAC_GEN1		0x00000001
#define SHE_TEST_MAC_GEN2		0x00000002
#define SHE_TEST_MAC_GEN_PERF	0x00000004
#define SHE_TEST_MAC_VERIF1		0x00000008
#define SHE_TEST_MAC_VERIF2		0x00000010
#define SHE_TEST_MAC_VERIF3		0x00000020
#define SHE_TEST_MAC_VERIF_PERF	0x00000040
#define SHE_TEST_LOAD_KEY		0x00000080
#define SHE_TEST_CBC_ENC1		0x00000100
#define SHE_TEST_CBC_ENC2		0x00000200
#define SHE_TEST_CBC_ENC_PERF	0x00000400
#define SHE_TEST_CBC_DEC1		0x00000800
#define SHE_TEST_CBC_DEC2		0x00001000
#define SHE_TEST_CBC_DEC_PERF	0x00002000
#define SHE_TEST_CBC_ENC3		0x00004000
#define SHE_TEST_MAC_GEN3		0x00008000
#define SHE_TEST_MAC_VERIF4		0x00010000
#define SHE_TEST_ECB_ENC		0x00020000
#define SHE_TEST_ECB_DEC		0x00040000
#define SHE_TEST_ECB_ENC_PERF	0x00080000
#define SHE_TEST_ECB_DEC_PERF	0x00100000

#define SHE_TEST_PERF	SHE_TEST_MAC_GEN_PERF | SHE_TEST_MAC_VERIF_PERF | SHE_TEST_CBC_ENC_PERF | SHE_TEST_CBC_DEC_PERF | SHE_TEST_ECB_ENC_PERF | SHE_TEST_ECB_DEC_PERF

/* default test list:
 * All tests without key loading
 */
#define SHE_TEST_DEFAULT        (0xFFFFFFFF & ~SHE_TEST_LOAD_KEY)
#define SHE_TEST_LEN_DEFAULT    10000
/* Genera purpose keys configuration (temporary static configuration)
 * KEY_1 - KEY_3 MAC GEN/VERIF
 * KEY_4 - KEY_7 MAC VERIF ONLY
 * KEY_8         ECB  encryption/decryption
 * KEY 9 - KEY_10 CBC encryption/decryption
*/

#define SHE_KEY_1								0x4
#define SHE_KEY_7								0xA
#define SHE_KEY_8								0xB
#define SHE_KEY_10								0xD
#define SHE_MASTER_ECU_KEY						0x1

#define SHE_KEY_N_EXT_0							0x0
#define SHE_KEY_N_EXT_1							0x1
#define SHE_KEY_N_EXT_2							0x2
#define SHE_KEY_N_EXT_3							0x3
#define SHE_KEY_N_EXT_4							0x4
/* Test MAC generation command - pattern 1. */
static void she_test_mac_gen1(struct she_hdl *hdl)
{
	she_err err;
	uint8_t key_id = SHE_KEY_N_EXT_1 << 0x4 | SHE_KEY_1;
	(void)printf("------------ MAC generation test 1 ----------------\n");
	err = she_cmd_generate_mac(hdl, key_id, MAC_TEST1_INPUT_SIZE, mac_input_message , mac_output);
	/* Check there is no error reported and that the generated MAC is correct. */
	if ((err != ERC_NO_ERROR) || memcmp(mac_output, mac_output_ref1, SHE_MAC_SIZE)) {
		(void)printf("\n--> ERROR 0x%x\n", err);
	} else {
		(void)printf("\n--> PASS\n");
	}
}


/* Test MAC generation command - pattern 2. */
static void she_test_mac_gen2(struct she_hdl *hdl)
{
	she_err err;
	uint8_t key_id = SHE_KEY_N_EXT_2 << 0x4 | SHE_KEY_1;

	(void)printf("------------ MAC generation test 2 ----------------\n");
	err = she_cmd_generate_mac(hdl, key_id, MAC_TEST2_INPUT_SIZE, mac_input_message, mac_output);
	/* Check there is no error reported and that the generated MAC is correct. */
	if ((err != ERC_NO_ERROR) || memcmp(mac_output, mac_output_ref2, SHE_MAC_SIZE)) {
		(void)printf("\n--> ERROR 0x%x\n", err);
	} else {
		(void)printf("\n--> PASS\n");
	}
}

/* Test MAC generation command - pattern 3. */
static void she_test_mac_gen3(struct she_hdl *hdl)
{
	she_err err;
	uint8_t key_id = SHE_KEY_N_EXT_3 << 0x4 | SHE_KEY_7;

	(void)printf("------------ MAC generation test 3 (KEY has flag VERIFY only) ----------------\n");
	err = she_cmd_generate_mac(hdl, key_id, MAC_TEST2_INPUT_SIZE, mac_input_message, mac_output);
	/* Check there is no error reported and that the generated MAC is correct. */
	if (err != ERC_KEY_INVALID) {
		(void)printf("\n--> ERROR 0x%x\n", err);
	} else {
		(void)printf("\n--> PASS (KEY is detected as invalid as expected)\n");
	}
}

/* Test MAC generation command - perf measurement. */
static void she_test_mac_gen_perf(struct she_hdl *hdl, uint32_t test_len)
{
	struct timespec ts1, ts2;
	uint64_t time_us;
	uint32_t l = test_len;
	uint8_t key_id = SHE_KEY_N_EXT_4 << 0x4 | SHE_KEY_1;

	if (test_len > 0) { /* To avoid a divide by 0 at the end ... */
		(void)printf("------------ MAC generation speed test ------------\n");
		(void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts1);
		while (l > 0) {
			/* Don't check result here. Just perf measurement. */
			(void)she_cmd_generate_mac(hdl, key_id, MAC_TEST1_INPUT_SIZE, mac_input_message , mac_output);
			l--;
		}
		/* Compute elapsed time. */
		(void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts2);
		time_us = (uint64_t)(ts2.tv_sec - ts1.tv_sec)*1000000 + (ts2.tv_nsec - ts1.tv_nsec)/1000;
		(void)printf("%d MAC generated in %ld microseconds (about %ld microseconds per MAC)\n", test_len, time_us, time_us/test_len);
	}
}


/* Test MAC verify command - pattern 1. */
static void she_test_mac_verif1(struct she_hdl *hdl)
{
	she_err err;
	uint8_t verif;
	uint8_t key_id = SHE_KEY_N_EXT_1 << 0x4 | SHE_KEY_1;

	(void)printf("------------ MAC verification test 1 ----------------\n");
	err = she_cmd_verify_mac(hdl, key_id, MAC_TEST1_INPUT_SIZE, mac_input_message , mac_output_ref1, SHE_MAC_SIZE, &verif);
	/* Check there is no error reported and that the verification is ok. */
	if ((err != ERC_NO_ERROR) || verif) {
		(void)printf("\n--> ERROR 0x%x\n", err);
	} else {
		(void)printf("\n--> PASS\n");
	}
}


/* Test MAC verify command - pattern 2. */
static void she_test_mac_verif2(struct she_hdl *hdl)
{
	she_err err;
	uint8_t verif;
	uint8_t key_id = SHE_KEY_N_EXT_2 << 0x4 | SHE_KEY_1;

	(void)printf("------------ MAC verification test 2 ----------------\n");
	err = she_cmd_verify_mac(hdl, key_id, MAC_TEST2_INPUT_SIZE, mac_input_message , mac_output_ref2, SHE_MAC_SIZE, &verif);
	/* Check there is no error reported and that the verification is ok. */
	if ((err != ERC_NO_ERROR) || verif) {
		(void)printf("\n--> ERROR 0x%x\n", err);
	} else {
		(void)printf("\n--> PASS\n");
	}
}


/* Test MAC verify command - pattern 3. */
static void she_test_mac_verif3(struct she_hdl *hdl)
{
	she_err err;
	uint8_t verif;
	uint8_t key_id = SHE_KEY_N_EXT_3 << 0x4 | SHE_KEY_1;

	(void)printf("------------ MAC verification test 3 (bad MAC) ------\n");
	err = she_cmd_verify_mac(hdl, key_id, MAC_TEST2_INPUT_SIZE, mac_input_message , mac_output_ref1, SHE_MAC_SIZE, &verif);
	/* This test expects a "no error" status but a verification status false. */
	if (err != ERC_NO_ERROR) {
		(void)printf("\n--> ERROR 0x%x\n", err);
	} else if (!verif) {
		(void)printf("\n--> ERROR (MAC verification status is true)\n");
	} else {
		(void)printf("\n--> PASS (MAC verification status is false as expected)\n");
	}
}

/* Test MAC verify command - pattern 4. */
static void she_test_mac_verif4(struct she_hdl *hdl)
{
	she_err err;
	uint8_t verif;

	(void)printf("------------ MAC verification test 4 (KEY cannot be used for MAC operations) ------\n");
	err = she_cmd_verify_mac(hdl, SHE_MASTER_ECU_KEY, MAC_TEST2_INPUT_SIZE, mac_input_message , mac_output_ref1, SHE_MAC_SIZE, &verif);
	/* This test expects a "no error" status but a verification status false. */
	if (err != ERC_KEY_INVALID) {
		(void)printf("\n--> ERROR 0x%x\n", err);
	} else {
		(void)printf("\n--> PASS (KEY is detected as invalid as expected)\n");
	}
}

/* Test MAC generation command - perf measurement. */
static void she_test_mac_verif_perf(struct she_hdl *hdl, uint32_t test_len)
{
	struct timespec ts1, ts2;
	uint64_t time_us;
	uint8_t verif;
	uint32_t l = test_len;
	uint8_t key_id = SHE_KEY_N_EXT_4 << 0x4 | SHE_KEY_1;

	if (test_len > 0) { /* To avoid a divide by 0 at the end ... */
		(void)printf("------------ MAC generation speed test ------------\n");
		(void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts1);
		while (l > 0) {
			/* Don't check result here. Just perf measurement. */
			(void)she_cmd_verify_mac(hdl, key_id, MAC_TEST1_INPUT_SIZE, mac_input_message , mac_output_ref1, SHE_MAC_SIZE, &verif);
			l--;
		}
		/* Compute elapsed time. */
		(void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts2);
		time_us = (uint64_t)(ts2.tv_sec - ts1.tv_sec)*1000000 + (ts2.tv_nsec - ts1.tv_nsec)/1000;
		(void)printf("%d MAC generated in %ld microseconds (about %ld microseconds per MAC)\n", test_len, time_us, time_us/test_len);
	}
}


/* Test CBC encryption . */
static void she_test_cbc_enc(struct she_hdl *hdl, uint32_t len)
{
	she_err err;
	uint8_t output[4*SHE_AES_BLOCK_SIZE_128];
	uint8_t key_id = SHE_KEY_N_EXT_1 << 0x4 | SHE_KEY_10;

	(void)printf("------------ CBC ENC test len:%d ----------------\n", len);

	err = she_cmd_enc_cbc(hdl, key_id, len, cbc_iv, cbc_plaintext, output);
	/* Check there is no error reported and that the generated MAC is correct. */

	if (err != ERC_NO_ERROR) {
		(void)printf("\n--> ERROR 0x%x\n", err);
	} else if (memcmp(output, cbc_ciphertext, len)) {
		(void)printf("\n--> Wrong output\n");
	} else {
		(void)printf("\n--> PASS\n");
	}
}

/* Test CBC encryption using wrong key idx . */
static void she_test_cbc_enc2(struct she_hdl *hdl, uint32_t len)
{
	she_err err;
	uint8_t output[4*SHE_AES_BLOCK_SIZE_128];
	uint8_t key_id = SHE_KEY_N_EXT_2 << 0x4 | SHE_KEY_7;

	(void)printf("------------ CBC ENC test (KEY cannot be used for enc/dec operations) ----------------\n");

	err = she_cmd_enc_cbc(hdl, key_id, len, cbc_iv, cbc_plaintext, output);
	/* Check there is no error reported and that the generated MAC is correct. */

	if (err != ERC_KEY_INVALID) {
		(void)printf("\n--> ERROR 0x%x\n", err);
	} else {
		(void)printf("\n--> PASS (KEY is detected as invalid as expected)\n");
	}
}

/* Test CBC encryption  - perf measurement. */
static void she_test_cbc_enc_perf(struct she_hdl *hdl, uint32_t test_len)
{
	struct timespec ts1, ts2;
	uint64_t time_us;
	uint8_t output[SHE_AES_BLOCK_SIZE_128];
	uint32_t l = test_len;
	uint8_t key_id = SHE_KEY_N_EXT_3 << 0x4 | SHE_KEY_10;

	if (test_len > 0) { /* To avoid a divide by 0 at the end ... */
		(void)printf("------------ CBC encrypt speed test ------------\n");
		(void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts1);
		while (l > 0) {
			/* Don't check result here. Just perf measurement. */
			(void)she_cmd_enc_cbc(hdl, key_id, SHE_AES_BLOCK_SIZE_128, cbc_iv, cbc_plaintext, output);
			l--;
		}
		/* Compute elapsed time. */
		(void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts2);
		time_us = (uint64_t)(ts2.tv_sec - ts1.tv_sec)*1000000 + (ts2.tv_nsec - ts1.tv_nsec)/1000;
		(void)printf("%d CBC encryptions in %ld microseconds (about %ld microseconds per CBC ENC)\n", test_len, time_us, time_us/test_len);
	}
}


/* Test CBC decryption. */
static void she_test_cbc_dec(struct she_hdl *hdl, uint32_t len)
{
	she_err err;
	uint8_t output[4*SHE_AES_BLOCK_SIZE_128];
	uint8_t key_id = SHE_KEY_N_EXT_4 << 0x4 | SHE_KEY_10;

	(void)printf("------------ CBC DEC test len:%d ----------------\n", len);

	err = she_cmd_dec_cbc(hdl, key_id, len, cbc_iv, cbc_ciphertext, output);
	/* Check there is no error reported and that the generated MAC is correct. */

	if (err != ERC_NO_ERROR) {
		(void)printf("\n--> ERROR 0x%x\n", err);
	} else if (memcmp(output, cbc_plaintext, len)) {
		(void)printf("\n--> Wrong output\n");
	} else {
		(void)printf("\n--> PASS\n");
	}
}


/* Test CBC decryption  - perf measurement. */
static void she_test_cbc_dec_perf(struct she_hdl *hdl, uint32_t test_len)
{
	struct timespec ts1, ts2;
	uint64_t time_us;
	uint8_t output[SHE_AES_BLOCK_SIZE_128];
	uint32_t l = test_len;
	uint8_t key_id = SHE_KEY_N_EXT_1 << 0x4 | SHE_KEY_10;

	if (test_len > 0) { /* To avoid a divide by 0 at the end ... */
		(void)printf("------------ CBC decrypt speed test ------------\n");
		(void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts1);
		while (l > 0) {
			/* Don't check result here. Just perf measurement. */
			(void)she_cmd_dec_cbc(hdl, key_id, SHE_AES_BLOCK_SIZE_128, cbc_iv, cbc_ciphertext, output);
			l--;
		}
		/* Compute elapsed time. */
		(void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts2);
		time_us = (uint64_t)(ts2.tv_sec - ts1.tv_sec)*1000000 + (ts2.tv_nsec - ts1.tv_nsec)/1000;
		(void)printf("%d CBC decryptions in %ld microseconds (about %ld microseconds per CBC DEC)\n", test_len, time_us, time_us/test_len);
	}
}


/* Test ECB encryption . */
static void she_test_ecb_enc(struct she_hdl *hdl)
{
	she_err err;
	uint8_t output[SHE_AES_BLOCK_SIZE_128];
	uint8_t key_id = SHE_KEY_N_EXT_1 << 0x4 | SHE_KEY_8;

	(void)printf("------------ ECB ENC test ----------------\n");

	err = she_cmd_enc_ecb(hdl, key_id, ecb_plaintext, output);
	/* Check there is no error reported and that the generated MAC is correct. */

	if (err != ERC_NO_ERROR) {
		(void)printf("\n--> ERROR 0x%x\n", err);
	} else if (memcmp(output, ecb_ciphertext, SHE_AES_BLOCK_SIZE_128)) {
		(void)printf("\n--> Wrong output\n");
	} else {
		(void)printf("\n--> PASS\n");
	}
}


/* Test ECB decryption . */
static void she_test_ecb_dec(struct she_hdl *hdl)
{
	she_err err;
	uint8_t output[SHE_AES_BLOCK_SIZE_128];
	uint8_t key_id = SHE_KEY_N_EXT_2 << 0x4 | SHE_KEY_8;

	(void)printf("------------ ECB ENC test ----------------\n");

	err = she_cmd_dec_ecb(hdl, key_id, ecb_ciphertext, output);
	/* Check there is no error reported and that the generated MAC is correct. */

	if (err != ERC_NO_ERROR) {
		(void)printf("\n--> ERROR 0x%x\n", err);
	} else if (memcmp(output, ecb_plaintext, SHE_AES_BLOCK_SIZE_128)) {
		(void)printf("\n--> Wrong output\n");
	} else {
		(void)printf("\n--> PASS\n");
	}
}



/* Test ECB encryption  - perf measurement. */
static void she_test_ecb_enc_perf(struct she_hdl *hdl, uint32_t test_len)
{
	struct timespec ts1, ts2;
	uint64_t time_us;
	uint8_t output[SHE_AES_BLOCK_SIZE_128];
	uint32_t l = test_len;
	uint8_t key_id = SHE_KEY_N_EXT_3 << 0x4 | SHE_KEY_8;

	if (test_len > 0) { /* To avoid a divide by 0 at the end ... */
		(void)printf("------------ ECB encrypt speed test ------------\n");
		(void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts1);
		while (l > 0) {
			/* Don't check result here. Just perf measurement. */
			(void)she_cmd_enc_ecb(hdl, key_id, ecb_plaintext, output);
			l--;
		}
		/* Compute elapsed time. */
		(void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts2);
		time_us = (uint64_t)(ts2.tv_sec - ts1.tv_sec)*1000000 + (ts2.tv_nsec - ts1.tv_nsec)/1000;
		(void)printf("%d ECB encryptions in %ld microseconds (about %ld microseconds per ECB ENC)\n", test_len, time_us, time_us/test_len);
	}
}



/* Test ECB decrypt  - perf measurement. */
static void she_test_ecb_dec_perf(struct she_hdl *hdl, uint32_t test_len)
{
	struct timespec ts1, ts2;
	uint64_t time_us;
	uint8_t output[SHE_AES_BLOCK_SIZE_128];
	uint32_t l = test_len;
	uint8_t key_id = SHE_KEY_N_EXT_4 << 0x4 | SHE_KEY_8;

	if (test_len > 0) { /* To avoid a divide by 0 at the end ... */
		(void)printf("------------ ECB decrypt speed test ------------\n");
		(void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts1);
		while (l > 0) {
			/* Don't check result here. Just perf measurement. */
			(void)she_cmd_dec_ecb(hdl, key_id, ecb_plaintext, output);
			l--;
		}
		/* Compute elapsed time. */
		(void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts2);
		time_us = (uint64_t)(ts2.tv_sec - ts1.tv_sec)*1000000 + (ts2.tv_nsec - ts1.tv_nsec)/1000;
		(void)printf("%d ECB decryptions in %ld microseconds (about %ld microseconds per ECB DEC)\n", test_len, time_us, time_us/test_len);
	}
}


/* Test load key command. */
static void she_test_load_key(struct she_hdl *hdl)
{
	she_err err;

	(void)printf("------------ load key test  ----------------\n");
	err = she_cmd_load_key(hdl);
	/* Check only that a success was reported. */
	if (err != ERC_NO_ERROR) {
		(void)printf("\n--> ERROR 0x%x\n", err);
	} else {
		(void)printf("\n--> PASS\n");
	}
}


static void she_test_sequence(struct she_hdl *hdl, uint32_t test_list, uint32_t test_len)
{
	/* Load key test is executed first so next tests can use the new key. */
	if (test_list & SHE_TEST_LOAD_KEY) {
		she_test_load_key(hdl);
	}
	/* MAC generation test - pattern 1. */
	if (test_list & SHE_TEST_MAC_GEN1) {
		she_test_mac_gen1(hdl);
	}
	/* MAC generation test - pattern 2. */
	if (test_list & SHE_TEST_MAC_GEN2) {
		she_test_mac_gen2(hdl);
	}
	/* MAC generation test - - wrong KEY. */
	if (test_list & SHE_TEST_MAC_GEN3) {
		she_test_mac_gen3(hdl);
	}
	/* MAC generation performance test. */
	if (test_list & SHE_TEST_MAC_GEN_PERF) {
		she_test_mac_gen_perf(hdl, test_len);
	}
	/* MAC verification test - pattern 1. */
	if (test_list & SHE_TEST_MAC_VERIF1) {
		she_test_mac_verif1(hdl);
	}
	/* MAC verification test - pattern 2. */
	if (test_list & SHE_TEST_MAC_VERIF2) {
		she_test_mac_verif2(hdl);
	}
	/* MAC verification test - wrong MAC. */
	if (test_list & SHE_TEST_MAC_VERIF3) {
		she_test_mac_verif3(hdl);
	}
	/* MAC verification test - wrong KEY. */
	if (test_list & SHE_TEST_MAC_VERIF4) {
		she_test_mac_verif4(hdl);
	}
	/* MAC verification performance test. */
	if (test_list & SHE_TEST_MAC_VERIF_PERF) {
		she_test_mac_verif_perf(hdl, test_len);
	}
	/* CBC encryption test. 1 block. */
	if (test_list & SHE_TEST_CBC_ENC1) {
		she_test_cbc_enc(hdl, SHE_AES_BLOCK_SIZE_128);
	}
	/* CBC encryption test. 4 blocks. */
	if (test_list & SHE_TEST_CBC_ENC2) {
		she_test_cbc_enc(hdl, 4*SHE_AES_BLOCK_SIZE_128);
	}
	/* CBC encryption test. bad key idx */
	if (test_list & SHE_TEST_CBC_ENC3) {
		she_test_cbc_enc2(hdl, 4*SHE_AES_BLOCK_SIZE_128);
	}
	/* CBC encryption performance test. */
	if (test_list & SHE_TEST_CBC_ENC_PERF) {
		she_test_cbc_enc_perf(hdl, test_len);
	}
	/* CBC decryption test. 1 block. */
	if (test_list & SHE_TEST_CBC_DEC1) {
		she_test_cbc_dec(hdl, SHE_AES_BLOCK_SIZE_128);
	}
	/* CBC encryption test. 4 blocks. */
	if (test_list & SHE_TEST_CBC_DEC2) {
		she_test_cbc_dec(hdl, 4*SHE_AES_BLOCK_SIZE_128);
	}
	/* CBC decryption performance test. */
	if (test_list & SHE_TEST_CBC_DEC_PERF) {
		she_test_cbc_dec_perf(hdl, test_len);
	}
	/* ECB encryption test.. */
	if (test_list & SHE_TEST_ECB_ENC) {
		she_test_ecb_enc(hdl);
	}
	/* ECB decryption test. */
	if (test_list & SHE_TEST_ECB_DEC) {
		she_test_ecb_dec(hdl);
	}
	/* ECB encryption test. perf test. */
	if (test_list & SHE_TEST_ECB_ENC_PERF) {
		she_test_ecb_enc_perf(hdl, test_len);
	}
	/* ECB decryption test. perf test */
	if (test_list & SHE_TEST_ECB_DEC_PERF) {
		she_test_ecb_dec_perf(hdl, test_len);
	}
}


/* Test entry function. */
int main(int argc, char *argv[])
{
	uint32_t test_list = SHE_TEST_DEFAULT;
	uint32_t test_len = SHE_TEST_LEN_DEFAULT;
	struct she_hdl *hdl = NULL;

	do {
		/* First argument is a bitfield of the test to be executed. */
		if (argc > 1) {
			test_list = strtoull(argv[1], NULL, 0);
		}
		/* Second arg is the number of iterations for perf tests. */
		if (argc > 2) {
			test_len = strtoull(argv[2], NULL, 0);
		}

		(void)printf("SHE tests starting (bitmap:0x%x perf tests:%d iterations)\n", test_list, test_len);

		/* Open the SHE session. */
		hdl = she_open_session();
		if (!hdl) {
			break;
		}

		/* Execute the tests. */
		she_test_sequence(hdl, test_list, test_len);

		(void)printf("SHE tests complete\n");
	} while(0);

	/* Close session if it was opened. */
	if (hdl) {
		she_close_session(hdl);
	}
}
