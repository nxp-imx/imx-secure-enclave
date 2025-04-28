// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#ifndef __test_hsm_manage_key_H__
#define __test_hsm_manage_key_H__

#include "hsm_exec.h"
#include "shx_test_macros.h"

uint32_t test_hsm_manage_key(hsm_test_struct_t *testCtx, FILE *fp);
uint32_t test_hsm_manage_key_ext(hsm_test_struct_t *testCtx, FILE *fp);
uint32_t test_hsm_bulk_manage_key(hsm_test_struct_t *testCtx, FILE *fp);

#endif // __test_hsm_manage_key_H__
