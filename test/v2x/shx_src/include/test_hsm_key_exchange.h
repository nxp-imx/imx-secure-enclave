// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#ifndef __test_hsm_key_exchange_H__
#define __test_hsm_key_exchange_H__

#include "hsm_exec.h"
#include "shx_test_macros.h"

uint32_t test_hsm_key_exchange(hsm_test_struct_t *testCtx, FILE *fp);
uint32_t test_hsm_full_key_exchange_sha_kek(hsm_test_struct_t *testCtx, FILE *fp);
uint32_t test_hsm_full_key_exchange_tls(hsm_test_struct_t *testCtx, FILE *fp);
uint32_t test_hsm_tls_finish(hsm_test_struct_t *testCtx, FILE *fp);

#endif // __test_hsm_key_exchange_H__
