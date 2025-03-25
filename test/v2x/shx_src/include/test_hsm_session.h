// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#ifndef __test_hsm_session_H__
#define __test_hsm_session_H__

#include "hsm_exec.h"
#include "shx_test_macros.h"

uint32_t test_hsm_open_session(hsm_test_struct_t *testCtx, FILE *fp);
uint32_t test_hsm_close_session(hsm_test_struct_t *testCtx, FILE *fp);

#endif // __test_hsm_session_H__

