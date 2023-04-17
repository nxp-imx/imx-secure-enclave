// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2019 NXP
 */

#ifndef __she_test_rng_h__
#define __she_test_rng_h__

#ifndef PSA_COMPLIANT
uint32_t she_test_rng_init(test_struct_t *testCtx, FILE *fp);
#endif

uint32_t she_test_extend_seed(test_struct_t *testCtx, FILE *fp);

uint32_t she_test_rnd(test_struct_t *testCtx, FILE *fp);

#endif  // __she_test_rng_h__
