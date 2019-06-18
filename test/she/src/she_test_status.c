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


/* get Status test*/
uint32_t she_test_get_status(test_struct_t *testCtx, FILE *fp)
{
    uint32_t fails = 0;

    she_err_t err = 1;

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

