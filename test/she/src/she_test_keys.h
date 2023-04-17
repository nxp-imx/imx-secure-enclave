// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2019 NXP
 */


#ifndef __she_test_keys_h__
#define __she_test_keys_h__

uint32_t she_test_load_key(test_struct_t *testCtx, FILE *fp);

uint32_t she_test_load_plain_key(test_struct_t *testCtx, FILE *fp);

uint32_t she_test_export_ram_key(test_struct_t *testCtx, FILE *fp);

#endif  // __she_test_keys_h__
