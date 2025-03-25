// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#ifndef __test_hsm_cipher_service_H__
#define __test_hsm_cipher_service_H__

#include "hsm_exec.h"
#include "shx_test_macros.h"

uint32_t test_hsm_open_cipher_service(hsm_test_struct_t *testCtx, FILE *fp);
uint32_t test_hsm_open_generic_crypto_service(hsm_test_struct_t *testCtx, FILE *fp);
uint32_t test_hsm_close_cipher_service(hsm_test_struct_t *testCtx, FILE *fp);

#endif // __test_hsm_cipher_service_H__
