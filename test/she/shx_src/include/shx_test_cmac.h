// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#ifndef __she_test_cmac_h__
#define __she_test_cmac_h__

uint32_t she_test_open_cmac_session(she_test_struct_t *testCtx, FILE *fp);
uint32_t she_test_close_cmac_session(she_test_struct_t *testCtx, FILE *fp);
uint32_t she_test_cmac_gen(she_test_struct_t *testCtx, FILE *fp);
uint32_t she_test_cmac_verif(she_test_struct_t *testCtx, FILE *fp);

#endif  // __she_test_cmac_h__
