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
#include "she_test_macros.h"

/* Test MAC generation command. */
uint32_t she_test_mac_gen(test_struct_t *testCtx, FILE *fp)
{
    uint32_t fails = 0;
    she_err_t err = 1;
    struct timespec ts1, ts2;

    uint8_t nb_iter = READ_VALUE(fp, uint8_t);

    uint32_t index = READ_VALUE(fp, uint32_t);
    uint8_t key_ext = READ_VALUE(fp, uint8_t);
    uint8_t key_id = READ_VALUE(fp, uint8_t);
    uint16_t input_size = READ_VALUE(fp, uint16_t);
    READ_INPUT_BUFFER(fp, input, input_size);
    READ_OUTPUT_BUFFER(fp, output, SHE_MAC_SIZE);

    (void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts1);

    for (uint32_t i=0; i<nb_iter; i++) {
        /* Call the API to be tested. */
        err = she_cmd_generate_mac(testCtx->hdl[index], key_ext, key_id, input_size, input, output);
    }

    (void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts2);

    /* check the last result */
    READ_CHECK_VALUE(fp, err);
        READ_CHECK_BUFFER(fp, output, SHE_MAC_SIZE);

    if (nb_iter > 1u) {
        print_perf(&ts1, &ts2, nb_iter);
    }

    return fails;
}

/* Test MAC verify command - pattern 1. */
uint32_t she_test_mac_verif(test_struct_t *testCtx, FILE *fp)
{
    uint32_t fails = 0;
    she_err_t err = 1;
    struct timespec ts1, ts2;

    uint8_t nb_iter = READ_VALUE(fp, uint8_t);

    uint32_t index = READ_VALUE(fp, uint32_t);
    uint8_t key_ext = READ_VALUE(fp, uint8_t);
    uint8_t key_id = READ_VALUE(fp, uint8_t);
    uint16_t input_size = READ_VALUE(fp, uint16_t);
    READ_INPUT_BUFFER(fp, input, input_size);
    uint8_t mac_size = READ_VALUE(fp, uint8_t);
    READ_INPUT_BUFFER(fp, input_mac, mac_size);
    READ_OUTPUT_BUFFER(fp, verif, 1);

    (void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts1);

    for (uint32_t i=0; i<nb_iter; i++) {
        /* Call the API to be tested. */
        err = she_cmd_verify_mac(testCtx->hdl[index], key_ext, key_id, input_size, input, input_mac, SHE_MAC_SIZE, verif);
    }

    (void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts2);

    /* check the last result */
    READ_CHECK_VALUE(fp, err);
    READ_CHECK_BUFFER(fp, verif, 1);

    if (nb_iter > 1u) {
        print_perf(&ts1, &ts2, nb_iter);
    }

    return fails;
}

