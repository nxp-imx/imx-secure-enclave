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
#include "nvm.h"
#include "she_api.h"
#include "she_test.h"
#include "she_test_mac.h"
#include "she_test_cbc.h"
#include "she_test_ecb.h"
#include "she_test_rng.h"
#include "she_test_status.h"
#include "she_test_keys.h"
#include "she_test_sessions.h"
#include "she_test_storage_create.h"
#include "she_test_storage_manager.h"

uint32_t read_single_data(FILE *fp)
{
    uint32_t value=0;
    char *line = NULL;
    size_t len = 0;
    ssize_t read;

    read = getline(&line, &len, fp);
    if (read > 0) {
        value = (uint32_t)strtoul(line, NULL, 0);
    }
#ifdef DEBUG
    printf("VALUE: 0x%x\n", value);
#endif
    free(line);
    return value;
}

void read_buffer(FILE *fp, uint8_t *dst, uint32_t size) {

    char *line = NULL;
    char *startptr = NULL;
    char *endptr = NULL;
    size_t len = 0;
    ssize_t read;
    uint32_t idx = 0;
    uint32_t data;

    while (idx < size) {
        read = getline(&line, &len, fp);
        if (read<0) {
            break;
        }
        startptr = line;

        data = strtoul(startptr, &endptr, 0);
        while (endptr != startptr) {
            dst[idx++] = (uint8_t)(data & 0xFFu);
            startptr = endptr + 1; /* skip separator */
            data = strtoul(startptr, &endptr, 0);
        }
    }

    free(line);
}

void read_buffer_ptr(FILE *fp, uint8_t **dst, uint32_t size) {

    char *line = NULL;
    char *startptr = NULL;
    char *endptr = NULL;
    size_t len = 0;
    ssize_t read;
    uint32_t idx = 0;
    uint32_t data;

    if (0 == size) {  // Always read one byte ... we have to support NULL for zero-length
        size = 1;
    }

    while (idx < size) {
        read = getline(&line, &len, fp);
        if (read<0) {
            break;
        }
        if ((read >= 4) && (0 == memcmp("NULL", line, 4))) {
            *dst = NULL;
            break;
        }

        uint8_t *d = *dst;

        startptr = line;

        data = strtoul(startptr, &endptr, 0);
        while (endptr != startptr) {
            d[idx++] = (uint8_t)(data & 0xFFu);
            startptr = endptr + 1; /* skip separator */
            data = strtoul(startptr, &endptr, 0);
        }
    }

    free(line);
}

uint32_t print_result(she_err_t err, she_err_t expected_err, uint8_t *output, uint8_t *expected_output, uint32_t output_size)
{
    /* Check there is no error reported and that the output is correct. */
    if (err != expected_err) {
        (void)printf("--> FAIL unexpected error: 0x%x\n", err);
    } else if ( (err == ERC_NO_ERROR) && (output_size > 0u) && (memcmp(output, expected_output, output_size) != 0)) {
        /* don't compare output for tests expecting an error as return code. */
        (void)printf("--> FAIL wrong output\n");
    } else {
        (void)printf("--> PASS\n");
        return 0;
    }
    return 1;
}

uint32_t print_perf(struct timespec *ts1, struct timespec *ts2, uint32_t nb_iter)
{
    uint64_t time_us;

    time_us = (uint64_t)(ts2->tv_sec - ts1->tv_sec)*1000000u + (ts2->tv_nsec - ts1->tv_nsec)/1000;
    uint32_t time_operation_us = (uint32_t)(time_us/nb_iter);
    (void)printf("%d microseconds per operation (%d iterations).\n", time_operation_us, nb_iter);
    return time_operation_us;
}


struct test_entry_t {
    const char *name;
    uint32_t (*func)(test_struct_t *testCtx, FILE *fp);
};


struct test_entry_t she_tests[] = {
    {"SHE_TEST_CBC_ENC", she_test_cbc_enc},
    {"SHE_TEST_CBC_DEC", she_test_cbc_dec},
    {"SHE_TEST_CLOSE_SESSION", she_test_close_session},
    {"SHE_TEST_ECB_ENC", she_test_ecb_enc},
    {"SHE_TEST_ECB_DEC", she_test_ecb_dec},
    {"SHE_TEST_EXPORT_RAM_KEY", she_test_export_ram_key},
    {"SHE_TEST_EXTEND_SEED", she_test_extend_seed},
    {"SHE_TEST_GET_STATUS",she_test_get_status},
    {"SHE_TEST_GET_ID",she_test_get_id},
    {"SHE_TEST_LOAD_KEY", she_test_load_key},
    {"SHE_TEST_LOAD_PLAIN_KEY", she_test_load_plain_key},
    {"SHE_TEST_MAC_GEN", she_test_mac_gen},
    {"SHE_TEST_MAC_VERIF", she_test_mac_verif},
    {"SHE_TEST_OPEN_SESSION", she_test_open_session},
    {"SHE_TEST_RNG_INIT", she_test_rng_init},
    {"SHE_TEST_RND", she_test_rnd},
    {"SHE_TEST_START_STORAGE_MANAGER", she_test_start_storage_manager},
    {"SHE_TEST_STOP_STORAGE_MANAGER", she_test_stop_storage_manager},
    {"SHE_TEST_STORAGE_CREATE", she_test_storage_create},
};


test_struct_t testCtx = { 0 };

/* Test entry function. */
int main(int argc, char *argv[])
{
    uint32_t fails = 0;

    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    uint16_t i;

    FILE *fp = NULL;

    uint32_t idx = 1;

    while (idx < argc) {

        do {

            fp = fopen(argv[idx], "r");
            if (fp == NULL) {
                printf("Can't open file: %s  --> FAIL\n", argv[idx]);
                break;
            }

            /* Indicate the start of a test */
            printf("\n<test>\n");

            printf("<filename>%s</filename>\n", argv[idx]);

            while( (read = getline(&line, &len, fp)) != -1) {
                if (line[0] == '<') {
                    (void)printf("%s", line);
                }
                else {
                    for (i=0; i < (sizeof(she_tests)/sizeof(struct test_entry_t)); i++) {
                        if (memcmp(line, she_tests[i].name, strlen(she_tests[i].name)) == 0) {
                            (void)printf("test: %s", line);
                            fails += she_tests[i].func(&testCtx, fp);
                            (void)printf("\n");
                        }
                    }
                }
            }

            if (NULL != line) {
                free(line);
                line = NULL;
            }

        } while(false);

        idx++;

        if (fp != NULL) {
            (void)fclose(fp);

            /* Indicate the end of a test */
            printf("\n</test>\n");
        }
    }

    return fails;
}
