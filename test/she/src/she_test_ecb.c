// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2019 NXP
 */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "she_api.h"
#include "she_test.h"
#include "she_test_macros.h"

/* Test ECB encryption .*/
uint32_t she_test_ecb_enc(test_struct_t *testCtx, FILE *fp)
{
    uint32_t fails = 0;
    she_err_t err = 1;
    struct timespec ts1, ts2;

    uint8_t nb_iter = READ_VALUE(fp, uint8_t);

    uint32_t index = READ_VALUE(fp, uint32_t);
    uint8_t key_ext = READ_VALUE(fp, uint8_t);
    uint8_t key_id = READ_VALUE(fp, uint8_t);
    READ_INPUT_BUFFER(fp, input, SHE_AES_BLOCK_SIZE_128);
    READ_OUTPUT_BUFFER(fp, output, SHE_AES_BLOCK_SIZE_128);

    (void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts1);

    for (uint32_t i=0; i<nb_iter; i++) {
        /* Call the API to be tested. */
        err = she_cmd_enc_ecb(testCtx->hdl[index], key_ext, key_id, input, output);
    }

    (void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts2);

    printf("SECO rating: 0x%x\n", she_get_last_rating_code(testCtx->hdl[index]));

    READ_CHECK_VALUE(fp, err);
    READ_CHECK_BUFFER(fp, output, SHE_AES_BLOCK_SIZE_128);

    if (nb_iter > 1u) {
        uint32_t avg_time_us = print_perf(&ts1, &ts2, nb_iter);
        READ_CHECK_RANGE(fp, avg_time_us);
    }

    return fails;
}

/* Test ECB decryption .*/
uint32_t she_test_ecb_dec(test_struct_t *testCtx, FILE *fp)
{
    uint32_t fails = 0;
    she_err_t err = 1;
    struct timespec ts1, ts2;

    uint8_t nb_iter = READ_VALUE(fp, uint8_t);

    uint32_t index = READ_VALUE(fp, uint32_t);
    uint8_t key_ext = READ_VALUE(fp, uint8_t);
    uint8_t key_id = READ_VALUE(fp, uint8_t);
    READ_INPUT_BUFFER(fp, input, SHE_AES_BLOCK_SIZE_128);
    READ_OUTPUT_BUFFER(fp, output, SHE_AES_BLOCK_SIZE_128);

    (void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts1);

    for (uint32_t i=0; i<nb_iter; i++) {
        /* Call the API to be tested. */
        err = she_cmd_dec_ecb(testCtx->hdl[index], key_ext, key_id, input, output);
    }

    (void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts2);

    printf("SECO rating: 0x%x\n", she_get_last_rating_code(testCtx->hdl[index]));

    READ_CHECK_VALUE(fp, err);
    READ_CHECK_BUFFER(fp, output, SHE_AES_BLOCK_SIZE_128);

    if (nb_iter > 1u) {
        uint32_t avg_time_us = print_perf(&ts1, &ts2, nb_iter);
        READ_CHECK_RANGE(fp, avg_time_us);
    }

    return fails;
}

