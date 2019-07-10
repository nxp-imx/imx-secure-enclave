/*
 * Copyright 2019 NXP
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
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "she_api.h"
#include "she_test.h"
#include "she_test_macros.h"

/* Test CBC encryption .*/
uint32_t she_test_cbc_enc(test_struct_t *testCtx, FILE *fp)
{
    uint32_t fails = 0;
    she_err_t err = 1;
    struct timespec ts1, ts2;

    /* read number of iterations */
    uint8_t nb_iter = READ_VALUE(fp, uint8_t);

    /* read function parameters */
    uint32_t index = READ_VALUE(fp, uint32_t);
    uint8_t key_ext = READ_VALUE(fp, uint8_t);
    uint8_t key_id = READ_VALUE(fp, uint8_t);
    uint32_t input_size = READ_VALUE(fp, uint32_t);
    READ_INPUT_BUFFER(fp, iv, SHE_AES_BLOCK_SIZE_128);
    READ_INPUT_BUFFER(fp, input, input_size);
    READ_OUTPUT_BUFFER(fp, output, input_size);

    (void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts1);

    for (uint32_t i=0; i<nb_iter; i++) {
        /* Call the API to be tested. */
        err = she_cmd_enc_cbc(testCtx->hdl[index], key_ext, key_id, input_size, iv, input, output);
        printf("SECO rating: 0x%x\n", she_get_last_rating_code(testCtx->hdl[index]));
    }

    (void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts2);

    /* check the last result */
    READ_CHECK_VALUE(fp, err);
    READ_CHECK_BUFFER(fp, output, input_size);

    if (nb_iter > 1u) {
        uint32_t avg_time_us = print_perf(&ts1, &ts2, nb_iter);
        READ_CHECK_RANGE(fp, avg_time_us);
    }

    return fails;
}

/* Test CBC decryption .*/
uint32_t she_test_cbc_dec(test_struct_t *testCtx, FILE *fp)
{
    uint32_t fails = 0;
    she_err_t err = 1;
    struct timespec ts1, ts2;

    /* read number of iterations */
    uint8_t nb_iter = READ_VALUE(fp, uint8_t);

    /* read function parameters */
    uint32_t index = READ_VALUE(fp, uint32_t);
    uint8_t key_ext = READ_VALUE(fp, uint8_t);
    uint8_t key_id = READ_VALUE(fp, uint8_t);
    uint32_t input_size = READ_VALUE(fp, uint32_t);
    READ_INPUT_BUFFER(fp, iv, SHE_AES_BLOCK_SIZE_128);
    READ_INPUT_BUFFER(fp, input, input_size);
    READ_OUTPUT_BUFFER(fp, output, input_size);

    (void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts1);

    for (uint32_t i=0; i<nb_iter; i++) {
        /* Call the API to be tested. */
        err = she_cmd_dec_cbc(testCtx->hdl[index], key_ext, key_id, input_size, iv, input, output);
        printf("SECO rating: 0x%x\n", she_get_last_rating_code(testCtx->hdl[index]));
    }

    (void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts2);

    /* check the last result */
    READ_CHECK_VALUE(fp, err);
    READ_CHECK_BUFFER(fp, output, input_size);

    if (nb_iter > 1u) {
        uint32_t avg_time_us = print_perf(&ts1, &ts2, nb_iter);
        READ_CHECK_RANGE(fp, avg_time_us);
    }

    return fails;
}


