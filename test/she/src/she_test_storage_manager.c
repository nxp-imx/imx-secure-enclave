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

#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "nvm.h"
#include "she_test.h"
#include "she_test_storage_manager.h"
#include "she_test_macros.h"

static uint32_t nvm_status;
uint8_t *nvm_fname_dname[] = {
	"/etc/ele_nvm_she/she_nvm_storage",
	"/etc/ele_nvm_she/"
};

static void *she_storage_thread(void *arg)
{
    nvm_manager(NVM_FLAGS_SHE, &nvm_status, nvm_fname_dname[0], nvm_fname_dname[1]);
}


/* Start the storage manager.*/
uint32_t she_test_start_storage_manager(test_struct_t *testCtx, FILE *fp)
{
    uint32_t fails = 0;
    
    nvm_status = NVM_STATUS_UNDEF;

    if (pthread_create(&(testCtx->tid), NULL, she_storage_thread, NULL) != 0) {
        fails = 1;
    }

    if (fails == 0) {
        /* Wait for the storage manager to be ready to receive commands from SECO. */
        while (nvm_status <= NVM_STATUS_STARTING) {
            usleep(1000);
        }
        /* Check if it ended because of an error. */
        if (nvm_status == NVM_STATUS_STOPPED) {
            fails = 1;
        }
    }

    return fails;
}


/* Test close session */
uint32_t she_test_stop_storage_manager(test_struct_t *testCtx, FILE *fp)
{
    uint32_t fails = 0;

    nvm_close_session();

    if (nvm_status != NVM_STATUS_STOPPED) {
        if (pthread_cancel(testCtx->tid) != 0) {
            fails = 1;
        }
    }

    return fails;
}

