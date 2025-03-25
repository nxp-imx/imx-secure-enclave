// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#ifndef __test_hsm_get_entropy_H__
#define __test_hsm_get_entropy_H__

#include "hsm_exec.h"
#include "shx_test_macros.h"

void place_hsm_in_privileged_mode(void);
uint32_t test_hsm_get_entropy(hsm_test_struct_t *testCtx, FILE *fp);
uint32_t test_hsm_open_entropy_file(hsm_test_struct_t *testCtx, FILE *fp);
uint32_t test_hsm_close_entropy_file(hsm_test_struct_t *testCtx, FILE *fp);
uint32_t test_hsm_sweep_noise_counter(hsm_test_struct_t *testCtx, FILE *fp);
uint32_t test_hsm_sweep_error_counter(hsm_test_struct_t *testCtx, FILE *fp);
uint32_t test_hsm_sweep_error_variance(hsm_test_struct_t *testCtx, FILE *fp);
uint32_t test_hsm_get_trng_freq(hsm_test_struct_t *testCtx, FILE *fp);

#endif // __test_hsm_get_entropy_H__
