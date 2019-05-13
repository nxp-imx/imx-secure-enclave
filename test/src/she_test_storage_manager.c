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
#include "she_storage.h"
#include "she_test.h"
#include "she_test_storage_manager.h"
#include "she_test_macros.h"

/* Start the storage manager.*/
uint32_t she_test_start_storage_manager(test_struct_t *testCtx, FILE *fp)
{
    uint32_t fails = 0;

    testCtx->storage_ctx = she_storage_init();

    she_err_t ptrOk;
    if (testCtx->storage_ctx != NULL) {
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
uint32_t she_test_stop_storage_manager(test_struct_t *testCtx, FILE *fp)
{
    if (testCtx->storage_ctx != NULL) {
        (void)she_storage_terminate(testCtx->storage_ctx);
    }
}

