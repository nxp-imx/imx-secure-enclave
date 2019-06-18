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


/* Test storage create */
uint32_t she_test_storage_create(test_struct_t *testCtx, FILE *fp)
{
    uint32_t fails = 0;

    she_err_t err = 1;
    she_err_t expected_err;

    uint32_t key_storage_identifier = READ_VALUE(fp, uint32_t);
    uint32_t password = READ_VALUE(fp, uint32_t);
    uint16_t max_updates_number = READ_VALUE(fp, uint16_t);
    uint32_t signed_message_length = READ_VALUE(fp, uint32_t);
    READ_INPUT_BUFFER(fp, signed_message, signed_message_length);

    err = she_storage_create( key_storage_identifier,
                              password,
                              max_updates_number,
                              signed_message,
                              signed_message_length );

    /* read the expected error code and check it. */
    READ_CHECK_VALUE(fp, err);

    return fails;
}

