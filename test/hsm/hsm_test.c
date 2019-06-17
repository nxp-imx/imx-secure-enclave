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
#include <unistd.h>

#include "hsm_api.h"
#include "seco_nvm.h"

/* Test entry function. */
int main(int argc, char *argv[])
{
    uint32_t hsm_session_hdl;
    uint32_t key_store_hdl;

    open_session_args_t open_session_args;
    open_svc_key_store_args_t open_svc_key_store_args;

    uint32_t nvm_status;

    hsm_err_t err;

    do {
        nvm_status = NVM_STATUS_UNDEF;
        seco_nvm_manager(NVM_FLAGS_HSM, &nvm_status);

        /* Wait for the storage manager to be ready to receive commands from SECO. */
        while (nvm_status <= NVM_STATUS_STARTING) {
            usleep(1000);
        }
        /* Check if it ended because of an error. */
        if (nvm_status == NVM_STATUS_STOPPED) {
            printf("nvm manager failed to start\n");
            /* Currently tolerate this error since not supported by SECO and not absolutely needed by APIs tested below. */
            // break;
        }

        open_session_args.session_priority = 0;
        open_session_args.operating_mode = 0;   
        err = hsm_open_session(&open_session_args,
                                    &hsm_session_hdl);
        if (err != HSM_NO_ERROR) {
            printf("hsm_open_session failed err:0x%x\n", err);
            break;
        }
        printf("hsm_open_session PASS\n");

        open_svc_key_store_args.key_store_identifier = 0xABCD;
        open_svc_key_store_args.authentication_nonce = 0x1234;
        open_svc_key_store_args.max_updates_number   = 100;
        open_svc_key_store_args.flags                = 0;
        err = hsm_open_key_store_service(hsm_session_hdl, &open_svc_key_store_args, &key_store_hdl);
        printf("hsm_open_key_store_service ret:0x%x\n", err);


        err = hsm_close_key_store_service(key_store_hdl);
        printf("hsm_close_key_store_service ret:0x%x\n", err);


        err = hsm_close_session(hsm_session_hdl);

        printf("hsm_close_session ret:0x%x\n", err);

    } while (0);
    return 0;
}
