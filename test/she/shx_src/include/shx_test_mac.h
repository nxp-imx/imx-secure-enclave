// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#ifndef __she_test_mac_h__
#define __she_test_mac_h__

uint32_t she_test_mac_gen(she_test_struct_t *testCtx, FILE *fp);

uint32_t she_test_mac_verif(she_test_struct_t *testCtx, FILE *fp);
uint32_t she_test_mac_verif_bit_ext(she_test_struct_t *testCtx, FILE *fp);

#endif  // __she_test_mac_h__
