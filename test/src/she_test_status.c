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


/* get Status test*/
uint32_t she_test_get_status(test_struct_t *testCtx, FILE *fp)
{
    uint32_t fails = 0;

    she_err_t err = 1;
    she_err_t expected_err;
    uint8_t status;
    uint8_t expected_status;

    /* read the session index. */
    uint32_t index = read_single_data(fp);

    expected_status = (uint8_t)read_single_data(fp);

    expected_err = (she_err_t)read_single_data(fp);

    err = she_cmd_get_status(testCtx->hdl[index], &status);

    fails += print_result(err, expected_err, &status, &expected_status, (uint32_t)sizeof(uint8_t));

    return fails;
}


/* get ID test*/
uint32_t she_test_get_id(test_struct_t *testCtx, FILE *fp)
{
    uint32_t fails = 0;

    she_err_t err = 1;
    she_err_t expected_err;
    uint8_t *challenge;
    uint8_t *output, *id, *mac, *status;
    uint8_t *reference, *id_ref, *mac_ref, *status_ref; 

    challenge = malloc(SHE_CHALLENGE_SIZE);
    read_buffer(fp, challenge, SHE_CHALLENGE_SIZE);

    output = malloc(SHE_ID_SIZE + SHE_MAC_SIZE + sizeof(uint8_t));
    id = output;
    mac = id + SHE_ID_SIZE;
    status = mac + SHE_MAC_SIZE;
    reference = malloc(SHE_ID_SIZE + SHE_MAC_SIZE + sizeof(uint8_t));
    id_ref = reference;
    mac_ref = id_ref + SHE_ID_SIZE;
    status_ref = mac_ref + SHE_MAC_SIZE;
    read_buffer(fp, id_ref, SHE_ID_SIZE);
    read_buffer(fp, mac_ref, SHE_MAC_SIZE);
    read_buffer(fp, status_ref, (uint32_t)sizeof(uint8_t));

    /* read the session index. */
    uint32_t index = read_single_data(fp);

    expected_err = (she_err_t)read_single_data(fp);

    err = she_cmd_get_id(testCtx->hdl[index], challenge, id, status, mac);

    fails += print_result(err, expected_err, output, reference, SHE_ID_SIZE + SHE_MAC_SIZE + (uint32_t)sizeof(uint8_t));

    free(reference);
    free(output);
    free(challenge);

    return fails;
}

