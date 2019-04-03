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
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "she_api.h"
#include "she_storage.h"

#define SHE_KEY_STORE_ID	0
#define SHE_KEY_STORE_PASSWORD	0xBEC00001

static uint32_t read_single_data(FILE *fp)
{
	uint32_t value=0;
	char *line = NULL;
	size_t len = 0;
	ssize_t read;

	read = getline(&line, &len, fp);
	if (read > 0) {
		value = (uint32_t)strtoul(line, NULL, 0);
	}
	free(line);
	return value;
}

static void read_buffer(FILE *fp, uint8_t *dst, uint32_t size) {

	char *line = NULL;
	char *startptr = NULL;
	char *endptr = NULL;
	size_t len = 0;
	ssize_t read;
	uint32_t idx = 0;
	uint32_t data;

	while (idx < size) {
		read = getline(&line, &len, fp);
		if (read<0) {
			break;
		}
		startptr = line;

		data = strtoul(startptr, &endptr, 0);
		while (endptr != startptr) {
			dst[idx++] = (uint8_t)(data & 0xFFu);
			startptr = endptr + 1; /* skip separator */
			data = strtoul(startptr, &endptr, 0);
		}
	}

	free(line);
}

static void print_result(she_err_t err, she_err_t expected_err, uint8_t *output, uint8_t *expected_output, uint32_t output_size)
{
	/* Check there is no error reported and that the output is correct. */
	if (err != expected_err) {
		(void)printf("--> FAIL unexpected error: 0x%x\n", err);
	} else if ( (err == ERC_NO_ERROR) && (output_size > 0u) && (memcmp(output, expected_output, output_size) != 0)) {
		/* don't compare output for tests expecting an error as return code. */
		(void)printf("--> FAIL wrong output\n");
	} else {
		(void)printf("--> PASS\n");
	}
}

static void print_perf(struct timespec *ts1, struct timespec *ts2, uint32_t nb_iter)
{
	uint64_t time_us;

	time_us = (uint64_t)(ts2->tv_sec - ts1->tv_sec)*1000000u + (ts2->tv_nsec - ts1->tv_nsec)/1000;
	(void)printf("%ld microseconds per operation (%d iterations).\n", time_us/nb_iter, nb_iter);
}


/* Test MAC generation command. */
static void she_test_mac_gen(struct she_hdl_s *hdl, FILE *fp)
{
	she_err_t err = 1;
	she_err_t expected_err;
	uint8_t key_id;
	uint8_t key_ext;
	uint32_t input_size;
	uint8_t *input = NULL;
	uint8_t *output = NULL;
	uint8_t *reference = NULL;
	struct timespec ts1, ts2;
	uint32_t nb_iter, i;

	/* read number of iterations */
	nb_iter = (uint8_t)read_single_data(fp);

	/* read key ID */
	key_id = (uint8_t)read_single_data(fp);

	/* read key extension */
	key_ext = (uint8_t)read_single_data(fp);

	/* read input length */
	input_size = read_single_data(fp);

	/* allocate memory for the input data and read them.*/
	input = malloc(input_size);
	read_buffer(fp, input, input_size);

	/* allocate memory for the output data and read the reference pattern.*/
	output = malloc(SHE_MAC_SIZE);
	reference = malloc(SHE_MAC_SIZE);
	read_buffer(fp, reference, SHE_MAC_SIZE);

	/* read the expected error code. */
	expected_err = (she_err_t)read_single_data(fp);

	(void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts1);

	for (i=0; i<nb_iter; i++) {
		/* Call the API to be tested. */
		err = she_cmd_generate_mac(hdl, key_ext, key_id, (uint16_t)input_size, input, output);
	}

	(void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts2);

	if (nb_iter > 1u) {
		print_perf(&ts1, &ts2, nb_iter);
	} else {
		print_result(err, expected_err, output, reference, SHE_MAC_SIZE);
	}
	free(input);
	free(output);
	free(reference);
}

/* Test MAC verify command - pattern 1. */
static void she_test_mac_verif(struct she_hdl_s *hdl, FILE *fp)
{
	she_err_t err = 1;
	she_err_t expected_err;
	uint8_t key_id;
	uint8_t key_ext;
	uint32_t input_size;
	uint8_t *input = NULL;
	uint8_t *input_mac = NULL;
	uint8_t verif = 1;
	uint8_t ref_verif = 1;
	struct timespec ts1, ts2;
	uint32_t nb_iter, i;

	/* read number of iterations */
	nb_iter = (uint8_t)read_single_data(fp);

	/* read key ID */
	key_id = (uint8_t)read_single_data(fp);

	/* read key extension */
	key_ext = (uint8_t)read_single_data(fp);

	/* read input length */
	input_size = read_single_data(fp);

	/* allocate memory for the input data and read them.*/
	input = malloc(input_size);
	read_buffer(fp, input, input_size);

	/* allocate memory for the input MAC and read it.*/
	input_mac = malloc(SHE_MAC_SIZE);
	read_buffer(fp, input_mac, SHE_MAC_SIZE);

	/* expected verification status. */
	ref_verif = read_single_data(fp);
	/* read the expected error code. */
	expected_err = (she_err_t)read_single_data(fp);


	(void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts1);

	for (i=0; i<nb_iter; i++) {
		/* Call the API to be tested. */
		err = she_cmd_verify_mac(hdl, key_ext, key_id, (uint16_t)input_size, input, input_mac, SHE_MAC_SIZE, &verif);
	}

	(void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts2);


	if (nb_iter > 1u) {
		print_perf(&ts1, &ts2, nb_iter);
	} else {
		print_result(err, expected_err, &verif, &ref_verif, (uint32_t)sizeof(verif));
	}

	free(input);
	free(input_mac);
}

/* Test CBC encryption .*/
static void she_test_cbc_enc(struct she_hdl_s *hdl, FILE *fp)
{
	she_err_t err = 1;
	she_err_t expected_err;
	uint8_t key_id;
	uint8_t key_ext;
	uint32_t input_size;
	uint8_t *iv = NULL;
	uint8_t *input = NULL;
	uint8_t *output = NULL;
	uint8_t *reference = NULL;
	struct timespec ts1, ts2;
	uint32_t nb_iter, i;

	/* read number of iterations */
	nb_iter = (uint8_t)read_single_data(fp);

	/* read key ID */
	key_id = (uint8_t)read_single_data(fp);

	/* read key extension */
	key_ext = (uint8_t)read_single_data(fp);

	/* read input length */
	input_size = read_single_data(fp);

	/* allocate memory for the IV and read it.*/
	iv = malloc(SHE_AES_BLOCK_SIZE_128);
	read_buffer(fp, iv, SHE_AES_BLOCK_SIZE_128);

	/* allocate memory for the input data and read them.*/
	input = malloc(input_size);
	read_buffer(fp, input, input_size);

	/* allocate memory for the output data and read the reference pattern.*/
	output = malloc(input_size);
	reference = malloc(input_size);
	read_buffer(fp, reference, input_size);

	/* read the expected error code. */
	expected_err = (she_err_t)read_single_data(fp);


	(void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts1);

	for (i=0; i<nb_iter; i++) {
		/* Call the API to be tested. */
		err = she_cmd_enc_cbc(hdl, key_ext, key_id, input_size, iv, input, output);
	}

	(void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts2);

	if (nb_iter > 1u) {
		print_perf(&ts1, &ts2, nb_iter);
	} else {
		print_result(err, expected_err, output, reference, input_size);
	}

	free(iv);
	free(input);
	free(output);
	free(reference);
}

/* Test CBC decryption .*/
static void she_test_cbc_dec(struct she_hdl_s *hdl, FILE *fp)
{
	she_err_t err = 1;
	she_err_t expected_err;
	uint8_t key_id;
	uint8_t key_ext;
	uint32_t input_size;
	uint8_t *iv = NULL;
	uint8_t *input = NULL;
	uint8_t *output = NULL;
	uint8_t *reference = NULL;
	struct timespec ts1, ts2;
	uint32_t nb_iter, i;

	/* read number of iterations */
	nb_iter = (uint8_t)read_single_data(fp);

	/* read key ID */
	key_id = (uint8_t)read_single_data(fp);

	/* read key extension */
	key_ext = (uint8_t)read_single_data(fp);

	/* read input length */
	input_size = read_single_data(fp);

	/* allocate memory for the IV and read it.*/
	iv = malloc(SHE_AES_BLOCK_SIZE_128);
	read_buffer(fp, iv, SHE_AES_BLOCK_SIZE_128);

	/* allocate memory for the input data and read them.*/
	input = malloc(input_size);
	read_buffer(fp, input, input_size);

	/* allocate memory for the output data and read the reference pattern.*/
	output = malloc(input_size);
	reference = malloc(input_size);
	read_buffer(fp, reference, input_size);

	/* read the expected error code. */
	expected_err = (she_err_t)read_single_data(fp);

	(void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts1);

	for (i=0; i<nb_iter; i++) {
		/* Call the API to be tested. */
		err = she_cmd_dec_cbc(hdl, key_ext, key_id, input_size, iv, input, output);
	}

	(void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts2);

	if (nb_iter > 1u) {
		print_perf(&ts1, &ts2, nb_iter);
	} else {
		print_result(err, expected_err, output, reference, input_size);
	}

	free(iv);
	free(input);
	free(output);
	free(reference);
}


/* Test ECB encryption .*/
static void she_test_ecb_enc(struct she_hdl_s *hdl, FILE *fp)
{
	she_err_t err = 1;
	she_err_t expected_err;
	uint8_t key_id;
	uint8_t key_ext;
	uint8_t *input = NULL;
	uint8_t *output = NULL;
	uint8_t *reference = NULL;
	struct timespec ts1, ts2;
	uint32_t nb_iter, i;

	/* read number of iterations */
	nb_iter = (uint8_t)read_single_data(fp);

	/* read key ID */
	key_id = (uint8_t)read_single_data(fp);

	/* read key extension */
	key_ext = (uint8_t)read_single_data(fp);

	/* allocate memory for the input data and read them.*/
	input = malloc(SHE_AES_BLOCK_SIZE_128);
	read_buffer(fp, input, SHE_AES_BLOCK_SIZE_128);

	/* allocate memory for the output data and read the reference pattern.*/
	output = malloc(SHE_AES_BLOCK_SIZE_128);
	reference = malloc(SHE_AES_BLOCK_SIZE_128);
	read_buffer(fp, reference, SHE_AES_BLOCK_SIZE_128);

	/* read the expected error code. */
	expected_err = (she_err_t)read_single_data(fp);

	(void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts1);

	for (i=0; i<nb_iter; i++) {
		/* Call the API to be tested. */
		err = she_cmd_enc_ecb(hdl, key_ext, key_id, input, output);
	}

	(void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts2);

	if (nb_iter > 1u) {
		print_perf(&ts1, &ts2, nb_iter);
	} else {
		print_result(err, expected_err, output, reference, SHE_AES_BLOCK_SIZE_128);
	}

	free(input);
	free(output);
	free(reference);
}

/* Test ECB decryption .*/
static void she_test_ecb_dec(struct she_hdl_s *hdl, FILE *fp)
{
	she_err_t err = 1;
	she_err_t expected_err;
	uint8_t key_id;
	uint8_t key_ext;
	uint8_t *input = NULL;
	uint8_t *output = NULL;
	uint8_t *reference = NULL;
	struct timespec ts1, ts2;
	uint32_t nb_iter, i;

	/* read number of iterations */
	nb_iter = (uint8_t)read_single_data(fp);

	/* read key ID */
	key_id = (uint8_t)read_single_data(fp);

	/* read key extension */
	key_ext = (uint8_t)read_single_data(fp);

	/* allocate memory for the input data and read them.*/
	input = malloc(SHE_AES_BLOCK_SIZE_128);
	read_buffer(fp, input, SHE_AES_BLOCK_SIZE_128);

	/* allocate memory for the output data and read the reference pattern.*/
	output = malloc(SHE_AES_BLOCK_SIZE_128);
	reference = malloc(SHE_AES_BLOCK_SIZE_128);
	read_buffer(fp, reference, SHE_AES_BLOCK_SIZE_128);

	/* read the expected error code. */
	expected_err = (she_err_t)read_single_data(fp);

	(void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts1);

	for (i=0; i<nb_iter; i++) {
		/* Call the API to be tested. */
		err = she_cmd_dec_ecb(hdl, key_ext, key_id, input, output);
	}

	(void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts2);

	if (nb_iter > 1u) {
		print_perf(&ts1, &ts2, nb_iter);
	} else {
		print_result(err, expected_err, output, reference, SHE_AES_BLOCK_SIZE_128);
	}

	free(input);
	free(output);
	free(reference);
}


/* Test load key */
static void she_test_load_key(struct she_hdl_s *hdl, FILE *fp)
{
	she_err_t err = 1;
	she_err_t expected_err;

	/* read the expected error code. */
	expected_err = (she_err_t)read_single_data(fp);
	err = she_cmd_load_key(hdl, NULL, NULL, NULL, NULL, NULL);

	/* Check there is no error reported. */
	print_result(err, expected_err, NULL, NULL, 0);
}


struct test_entry_t {
	const char *name;
	void (*func)(struct she_hdl_s *hdl, FILE *fp);
};


struct test_entry_t she_tests[] = {
	{"SHE_TEST_MAC_GEN", she_test_mac_gen},
	{"SHE_TEST_MAC_VERIF", she_test_mac_verif},
	{"SHE_TEST_CBC_ENC", she_test_cbc_enc},
	{"SHE_TEST_CBC_DEC", she_test_cbc_dec},
	{"SHE_TEST_ECB_ENC", she_test_ecb_enc},
	{"SHE_TEST_ECB_DEC", she_test_ecb_dec},
	{"SHE_TEST_LOAD_KEY", she_test_load_key},
};


/* Test entry function. */
int main(int argc, char *argv[])
{
	struct she_hdl_s *hdl = NULL;
	struct she_storage_context *storage_ctx = NULL;
	char *line = NULL;
	size_t len = 0;
	ssize_t read;
	uint16_t i;

	FILE *fp = NULL;

	do {
		if (argc != 2) {
			break;
		}

		fp = fopen(argv[1], "r");
		if (fp == NULL) {
			break;
		}

		/* Start the storage manager.*/
		storage_ctx = she_storage_init();
		if (storage_ctx == NULL) {
			break;
		}

		/* Open the SHE session. */
		hdl = she_open_session(SHE_KEY_STORE_ID, SHE_KEY_STORE_PASSWORD);
		if (hdl == NULL) {
			break;
		}

		while( (read = getline(&line, &len, fp)) != -1) {
			for (i=0; i < (sizeof(she_tests)/sizeof(struct test_entry_t)); i++) {
				if (memcmp(line, she_tests[i].name, strlen(she_tests[i].name)) == 0) {
					(void)printf("test: %s", line);
					she_tests[i].func(hdl, fp);
					(void)printf("\n");
				}
			}
		}
		free(line);
	} while(false);

	/* Close session if it was opened. */
	if (hdl != NULL) {
		she_close_session(hdl);
	}
	if (storage_ctx != NULL) {
		(void)she_storage_terminate(storage_ctx);
	}
	if (fp != NULL) {
		(void)fclose(fp);
	}
}
