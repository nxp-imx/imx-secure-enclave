// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#ifndef __she_test_rng_h__
#define __she_test_rng_h__

uint32_t she_test_rng_init(she_test_struct_t *testCtx, FILE *fp);

uint32_t she_test_extend_seed(she_test_struct_t *testCtx, FILE *fp);

uint32_t she_test_rnd(she_test_struct_t *testCtx, FILE *fp);

uint32_t she_test_rng_close(she_test_struct_t *testCtx, FILE *fp);

#endif  // __she_test_rng_h__
