// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#ifndef __she_test_sessions_h__
#define __she_test_sessions_h__

uint32_t she_test_open_session(she_test_struct_t *testCtx, FILE *fp);

uint32_t she_test_close_session(she_test_struct_t *testCtx, FILE *fp);

#endif  // __she_test_open_sessions_h__
