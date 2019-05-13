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
#include "she_storage.h"
#include "she_test.h"
#include "she_test_macros.h"


/* Test load key */
uint32_t she_test_load_key(test_struct_t *testCtx, FILE *fp)
{
    uint32_t fails = 0;

    she_err_t err = 1;
    she_err_t expected_err;

    /* read the session index. */
    uint32_t index = READ_VALUE(fp, uint32_t);

    // These macros define buffers and use pointers so that
    // we can replace them with values, if specified
    uint8_t key_ext = READ_VALUE(fp, uint8_t);
    uint8_t key_id = READ_VALUE(fp, uint8_t);
    READ_INPUT_BUFFER(fp, m1, 16u);  // input: 128 bits
    READ_INPUT_BUFFER(fp, m2, 32u);  // input: 256 bits
    READ_INPUT_BUFFER(fp, m3, 16u);  // input: 128 bits
    READ_OUTPUT_BUFFER(fp, m4, 32u);  // output: 256 bits
    READ_OUTPUT_BUFFER(fp, m5, 16u);  // output: 128 bits

    err = she_cmd_load_key(testCtx->hdl[index], key_ext, key_id, m1, m2, m3, m4, m5);

    /* read the expected error code and check it. */
    READ_CHECK_VALUE(fp, err);

    /* read the expected buffer values */
    READ_CHECK_BUFFER(fp, m4, 32u);
    READ_CHECK_BUFFER(fp, m5, 16u);

    return fails;
}


/* Test load plain key */
uint32_t she_test_load_plain_key(test_struct_t *testCtx, FILE *fp)
{
    uint32_t fails = 0;

    she_err_t err = 1;

    /* read the session index. */
    uint32_t index = READ_VALUE(fp, uint32_t);

    /* read the key parameter */
    READ_INPUT_BUFFER(fp, key, 16u);  // input: 128 bits

    err = she_cmd_load_plain_key(testCtx->hdl[index], key);

    /* read the expected error code and check it. */
    READ_CHECK_VALUE(fp, err);

    return fails;
}


/* Test export ram key */
uint32_t she_test_export_ram_key(test_struct_t *testCtx, FILE *fp)
{
    uint32_t fails = 0;

    she_err_t err = 1;
    she_err_t expected_err;

    /* read the session index. */
    uint32_t index = READ_VALUE(fp, uint32_t);

    READ_OUTPUT_BUFFER(fp, m1, 16u);  // input: 128 bits
    READ_OUTPUT_BUFFER(fp, m2, 32u);  // input: 256 bits
    READ_OUTPUT_BUFFER(fp, m3, 16u);  // input: 128 bits
    READ_OUTPUT_BUFFER(fp, m4, 32u);  // output: 256 bits
    READ_OUTPUT_BUFFER(fp, m5, 16u);  // output: 128 bits

    err = she_cmd_export_ram_key(testCtx->hdl[index], m1, m2, m3, m4, m5);

    /* read the expected error code and check it. */
    READ_CHECK_VALUE(fp, err);

    READ_CHECK_BUFFER(fp, m1, 16u);  // input: 128 bits
    READ_CHECK_BUFFER(fp, m2, 32u);  // input: 256 bits
    READ_CHECK_BUFFER(fp, m3, 16u);  // input: 128 bits
    READ_CHECK_BUFFER(fp, m4, 32u);  // output: 256 bits
    READ_CHECK_BUFFER(fp, m5, 16u);  // output: 128 bits

    return fails;
}

