// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#ifndef __she_test_status_h__
#define __she_test_status_h__

uint32_t she_test_get_id(she_test_struct_t *testCtx, FILE *fp);

uint32_t she_test_get_status(she_test_struct_t *testCtx, FILE *fp);

uint32_t she_test_get_last_rating_code(she_test_struct_t *testCtx, FILE *fp);

uint32_t she_test_get_info(she_test_struct_t *testCtx, FILE *fp);

#endif  // __she_test_status_h__
