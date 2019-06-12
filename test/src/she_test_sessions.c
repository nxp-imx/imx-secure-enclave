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
#include "she_test_sessions.h"
#include "she_test_macros.h"

/* Test open session */
uint32_t she_test_open_session(test_struct_t *testCtx, FILE *fp)
{
    uint32_t fails = 0;

    /* read the parameters. */
    uint32_t hdl_index = read_single_data(fp);
    uint32_t key_storage_identifier = READ_VALUE(fp, uint32_t);
    uint32_t password = READ_VALUE(fp, uint32_t);

    /* Open the SHE session. */
    testCtx->hdl[hdl_index] = she_open_session(key_storage_identifier, password, NULL, NULL);

    she_err_t ptrOk;
    if (testCtx->hdl[hdl_index] != NULL) {
        ptrOk = 1;
    }
    else {
        ptrOk = 0;
    }

    /* Check there is no error reported. */
    READ_CHECK_VALUE(fp, ptrOk);

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

