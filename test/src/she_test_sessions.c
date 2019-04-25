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
#include "she_test_sessions.h"

/* Test open session */
uint32_t she_test_open_session(test_struct_t *testCtx, FILE *fp)
{
    uint32_t fails = 0;

    /* struct she_hdl_s *she_open_session(uint32_t key_storage_identifier, uint32_t password); */

    /* read the parameters. */
    uint32_t hdl_index = read_single_data(fp);
    uint32_t key_storage_identifier = read_single_data(fp);
    uint32_t password = read_single_data(fp);

    /* read the expected error code. */
    she_err_t expected_err = (she_err_t)read_single_data(fp);

    /* Open the SHE session. */
    testCtx->hdl[hdl_index] = she_open_session(key_storage_identifier, password);

    she_err_t err;
    if (testCtx->hdl[hdl_index] != NULL) {
        err = 1;
    }
    else {
        err = 0;
    }

    /* Check there is no error reported. */
    fails += print_result(err, expected_err, NULL, NULL, 0);

    return fails;
}


/* Test close session */
uint32_t she_test_close_session(test_struct_t *testCtx, FILE *fp)
{
    /* read the session index. */
    uint32_t index = read_single_data(fp);

    /* Close session if it was opened. */
    she_close_session(testCtx->hdl[index]);
}

