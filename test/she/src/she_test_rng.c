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

/* Tests for RNG */

uint32_t she_test_rng_init(test_struct_t *testCtx, FILE *fp) {
    uint32_t fails = 0;

    she_err_t err = 1;
    she_err_t expected_err;

    /* read the session index. */
    uint32_t index = READ_VALUE(fp, uint32_t);

    err = she_cmd_init_rng(testCtx->hdl[index]);

    READ_CHECK_VALUE(fp, err);

    return fails;
}


uint32_t she_test_extend_seed(test_struct_t *testCtx, FILE *fp) {
    uint32_t fails = 0;

    she_err_t err = 1;
    she_err_t expected_err;

    /* read the session index. */
    uint32_t index = READ_VALUE(fp, uint32_t);

    READ_INPUT_BUFFER(fp, entropy, SHE_ENTROPY_SIZE);

    err = she_cmd_extend_seed(testCtx->hdl[index], entropy);

    READ_CHECK_VALUE(fp, err);

    return fails;
}


uint32_t she_test_rnd(test_struct_t *testCtx, FILE *fp) {
    uint32_t fails = 0;

    she_err_t err = 1;
    she_err_t expected_err;

    /* read the session index. */
    uint32_t index = READ_VALUE(fp, uint32_t);

    READ_OUTPUT_BUFFER(fp, rnd, SHE_RND_SIZE);

    err = she_cmd_rnd(testCtx->hdl[index], rnd);

    /* read the expected error code. */
    READ_CHECK_VALUE(fp, err);

    /* Print the generated number. */
    dump_buffer(rnd, SHE_RND_SIZE);

    return fails;
}

