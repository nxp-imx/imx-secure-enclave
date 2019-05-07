
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
#include "hsm_api.h"
#include "hsm_storage.h"

/* Test entry function. */
int main(int argc, char *argv[])
{
    uint32_t fails = 0;
    struct hsm_storage_context *nvm_ctx;

    uint32_t hsm_session_hdl;
    open_session_args_t open_session_args;

    hsm_err_t err;

    do {
        nvm_ctx = hsm_storage_init();
        if (!nvm_ctx) {
            printf("hsm_storage_init failed\n");
            //break;
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

        err = hsm_close_session(hsm_session_hdl);

        printf("hsm_close_session ret:0x%x\n", err);

        if (nvm_ctx) {
            hsm_storage_terminate(nvm_ctx);
            printf("HSM storage manager closed\n");
        }
    } while (0);
    return fails;
}
