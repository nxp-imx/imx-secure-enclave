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


/* get Status test*/
uint32_t she_test_get_status(test_struct_t *testCtx, FILE *fp)
{
    uint32_t fails = 0;

    she_err_t err = 1;
    she_err_t expected_err;

    /* read the session index. */
    uint32_t index = READ_VALUE(fp, uint32_t);
    READ_OUTPUT_BUFFER(fp, status, 1);

    err = she_cmd_get_status(testCtx->hdl[index], status);

    READ_CHECK_VALUE(fp, err);
    READ_CHECK_BUFFER(fp, status, 1);

    return fails;
}


/* get ID test*/
uint32_t she_test_get_id(test_struct_t *testCtx, FILE *fp)
{
    uint32_t fails = 0;

    she_err_t err = 1;

    /* read the session index. */
    uint32_t index = READ_VALUE(fp, uint32_t);

    READ_INPUT_BUFFER(fp, challenge, SHE_CHALLENGE_SIZE);
    READ_OUTPUT_BUFFER(fp, id, SHE_ID_SIZE);
    READ_OUTPUT_BUFFER(fp, status, sizeof(uint8_t));
    READ_OUTPUT_BUFFER(fp, mac, SHE_MAC_SIZE);

    /* Execute the command */
    err = she_cmd_get_id(testCtx->hdl[index], challenge, id, status, mac);

    /* Check the results */
    READ_CHECK_VALUE(fp, err);

    READ_CHECK_BUFFER(fp, id, SHE_ID_SIZE);
    READ_CHECK_BUFFER(fp, status, sizeof(uint8_t));
    READ_CHECK_BUFFER(fp, mac, SHE_MAC_SIZE);

    return fails;
}

