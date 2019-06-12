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

#ifndef __she_test_h__
#define __she_test_h__

#include "she_api.h"

typedef struct
{
	struct she_storage_context *storage_ctx;
    struct she_hdl_s *hdl[16];
    pthread_t tid;
} test_struct_t;

uint32_t read_single_data(FILE *fp);

void read_buffer(FILE *fp, uint8_t *dst, uint32_t size);

void read_buffer_ptr(FILE *fp, uint8_t **dst, uint32_t size);

uint32_t print_result(she_err_t err, she_err_t expected_err, uint8_t *output, uint8_t *expected_output, uint32_t output_size);

uint32_t print_perf(struct timespec *ts1, struct timespec *ts2, uint32_t nb_iter);

#endif  // __she_test_h__
