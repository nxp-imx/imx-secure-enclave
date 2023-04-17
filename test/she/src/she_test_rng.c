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

/* Tests for RNG */

#ifndef PSA_COMPLIANT
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
#endif

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

