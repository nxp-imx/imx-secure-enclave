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

#ifndef __she_test_rng_h__
#define __she_test_rng_h__

#ifndef PSA_COMPLIANT
uint32_t she_test_rng_init(test_struct_t *testCtx, FILE *fp);
#endif

uint32_t she_test_extend_seed(test_struct_t *testCtx, FILE *fp);

uint32_t she_test_rnd(test_struct_t *testCtx, FILE *fp);

#endif  // __she_test_rng_h__
