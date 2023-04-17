// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2019 NXP
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


void she_print_infos(struct she_hdl_s *hdl)
{
    she_err_t err;
    uint32_t user_sab_id;
    uint8_t chip_unique_id[8];
    uint16_t chip_monotonic_counter;
    uint16_t chip_life_cycle;
    uint32_t she_version;

    err = she_get_info(hdl, &user_sab_id, chip_unique_id, &chip_monotonic_counter, &chip_life_cycle, &she_version);

    if (err == ERC_NO_ERROR) {
        printf("SHE infos: user_sab_id:             0x%08x\n", user_sab_id);
        printf("SHE infos: chip_unique_id:          0x%02x%02x%02x%02x%02x%02x%02x%02x\n",
                                                        chip_unique_id[7],
                                                        chip_unique_id[6],
                                                        chip_unique_id[5],
                                                        chip_unique_id[4],
                                                        chip_unique_id[3],
                                                        chip_unique_id[2],
                                                        chip_unique_id[1],
                                                        chip_unique_id[0]);
        printf("SHE infos: chip_monotonic_counter:  0x%04x\n", chip_monotonic_counter);
        printf("SHE infos: chip_life_cycle:         0x%04x\n", chip_life_cycle);
        printf("SHE infos: she_version:             0x%08x\n", she_version);
    } else {
        printf("SHE infos error 0x%x\n", err);
        printf("SECO rating: 0x%x\n", she_get_last_rating_code(hdl));
    }
}

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
        she_print_infos(testCtx->hdl[hdl_index]);
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
