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
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIE
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
    READ_INPUT_BUFFER(fp, m1, 16u);  // input: 128 bits
    READ_INPUT_BUFFER(fp, m2, 32u);  // input: 256 bits
    READ_INPUT_BUFFER(fp, m3, 16u);  // input: 128 bits
    READ_OUTPUT_BUFFER(fp, m4, 32u);  // output: 256 bits
    READ_OUTPUT_BUFFER(fp, m5, 16u);  // output: 128 bits

    err = she_cmd_load_key(testCtx->hdl[index], m1, m2, m3, m4, m5);

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

