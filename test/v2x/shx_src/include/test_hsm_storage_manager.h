// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#ifndef __test_hsm_storage_manager_h__
#define __test_hsm_storage_manager_h__

#include "hsm_exec.h"

uint32_t test_hsm_start_storage_manager(hsm_test_struct_t *testCtx, FILE *fp);
uint32_t test_hsm_stop_storage_manager(hsm_test_struct_t *testCtx, FILE *fp);
uint32_t test_hsm_start_v2x_storage_manager(hsm_test_struct_t *testCtx, FILE *fp);
uint32_t test_hsm_stop_v2x_storage_manager(hsm_test_struct_t *testCtx, FILE *fp);

#endif  // __test_hsm_storage_manager_h__

