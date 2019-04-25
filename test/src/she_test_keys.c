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


/* Test load key */
uint32_t she_test_load_key(test_struct_t *testCtx, FILE *fp)
{
    uint32_t fails = 0;

    she_err_t err = 1;
    she_err_t expected_err;

    /* read the session index. */
    uint32_t index = read_single_data(fp);

    uint8_t *m1 = malloc(16u);  // input: 128 bits
    uint8_t *m2 = malloc(32u);  // input: 256 bits
    uint8_t *m3 = malloc(16u);  // input: 128 bits
    uint8_t *m4 = malloc(32u);  // output: 256 bits
    uint8_t *m5 = malloc(16u);  // output: 128 bits
    uint8_t *exp_m4 = malloc(32u);  // compare: 256 bits
    uint8_t *exp_m5 = malloc(16u);  // compare: 128 bits

    // Use pointers here so that we can replace them with values, if specified
    uint8_t *m[5] = { m1, m2, m3, m4, m5 };
    uint8_t *exp_m[2] = { exp_m4, exp_m5 };

    read_buffer_ptr(fp, &m[0], 16);  // read-or-replace all 5 buffer parameters
    read_buffer_ptr(fp, &m[1], 32);  //   This implementation allows replacing a pointer with NULL
    read_buffer_ptr(fp, &m[2], 16);
    read_buffer_ptr(fp, &m[3], 32);
    read_buffer_ptr(fp, &m[4], 16);

    /* read the expected error code. */
    expected_err = (she_err_t)read_single_data(fp);

    /* read expected buffers for m4 and m5 */
    read_buffer_ptr(fp, &exp_m[0], 32);
    read_buffer_ptr(fp, &exp_m[1], 16);

    printf("m1:   %p\n", m[0]);
    printf("m2:   %p\n", m[1]);
    printf("m3:   %p\n", m[2]);
    printf("m4:   %p\n", m[3]);
    printf("m5:   %p\n", m[4]);
    printf("exp4: %p\n", exp_m[0]);
    printf("exp5: %p\n", exp_m[1]);

    err = she_cmd_load_key(testCtx->hdl[index], m[0], m[1], m[2], m[3], m[4]);

    /* Check there is no error reported. */
    fails += print_result(err, expected_err, NULL, NULL, 0);
    if (exp_m[0]) {
        printf("Check m4: ");
        fails += print_result(0, 0, m[3], exp_m[0], 32);
    }
    if (exp_m[1]) {
        printf("Check m5: ");
        fails += print_result(0, 0, m[4], exp_m[1], 16);
    }

    free(exp_m5);
    free(exp_m4);
    free(m5);
    free(m4);
    free(m3);
    free(m2);
    free(m1);

    return fails;
}


/* Test load plain key */
uint32_t she_test_load_plain_key(test_struct_t *testCtx, FILE *fp)
{
    uint32_t fails = 0;

    she_err_t err = 1;
    she_err_t expected_err;
    uint8_t *key;

    /* read the session index. */
    uint32_t index = read_single_data(fp);

    key = malloc(SHE_KEY_SIZE);
    read_buffer(fp, key, SHE_KEY_SIZE);

    /* read the expected error code. */
    expected_err = (she_err_t)read_single_data(fp);

    err = she_cmd_load_plain_key(testCtx->hdl[index], key);

    /* Check there is no error reported. */
    fails += print_result(err, expected_err, NULL, NULL, 0);

    free(key);

    return fails;
}
