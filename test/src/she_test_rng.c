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

/* Tests for RNG */

uint32_t she_test_rng_init(struct she_hdl_s *hdl, FILE *fp) {
    uint32_t fails = 0;

    she_err_t err = 1;
    she_err_t expected_err;

    /* read the expected error code. */
    expected_err = (she_err_t)read_single_data(fp);

    err = she_cmd_init_rng(hdl);

    /* Check there is no error reported. */
    fails += print_result(err, expected_err, NULL, NULL, 0);

    return fails;
}


uint32_t she_test_extend_seed(struct she_hdl_s *hdl, FILE *fp) {
    uint32_t fails = 0;

    she_err_t err = 1;
    she_err_t expected_err;
    uint8_t *entropy;

    entropy = malloc(SHE_ENTROPY_SIZE);
    read_buffer(fp, entropy, SHE_ENTROPY_SIZE);

    /* read the expected error code. */
    expected_err = (she_err_t)read_single_data(fp);

    err = she_cmd_extend_seed(hdl, entropy);

    /* Check there is no error reported. */
    fails += print_result(err, expected_err, NULL, NULL, 0);

    free(entropy);

    return fails;
}


uint32_t she_test_rnd(struct she_hdl_s *hdl, FILE *fp) {
    uint32_t fails = 0;

    she_err_t err = 1;
    she_err_t expected_err;
    uint8_t *rnd;
    uint8_t *rnd_ref;
    uint32_t i;

    rnd = malloc(SHE_RND_SIZE);

    /* read the expected error code. */
    expected_err = (she_err_t)read_single_data(fp);

    err = she_cmd_rnd(hdl, rnd);

    for (i=0; i<SHE_RND_SIZE; i++) {
        printf("0x%x ", rnd[i]);
        if (i%4 == 3) {
            printf("\n");
        }
    }

    /* Print the generated number. */

    /* Check there is no error reported. */
    fails += print_result(err, expected_err, NULL, NULL, 0);

    free(rnd);
    free(rnd_ref);

    return fails;
}

