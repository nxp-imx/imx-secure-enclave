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
#include "she_test.h"

/* Test ECB encryption .*/
uint32_t she_test_ecb_enc(struct she_hdl_s *hdl, FILE *fp)
{
    uint32_t fails = 0;

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
        fails += print_result(err, expected_err, output, reference, SHE_AES_BLOCK_SIZE_128);
    }

    free(input);
    free(output);
    free(reference);

    return fails;
}

/* Test ECB decryption .*/
uint32_t she_test_ecb_dec(struct she_hdl_s *hdl, FILE *fp)
{
    uint32_t fails = 0;

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
        fails += print_result(err, expected_err, output, reference, SHE_AES_BLOCK_SIZE_128);
    }

    free(input);
    free(output);
    free(reference);

    return fails;
}

