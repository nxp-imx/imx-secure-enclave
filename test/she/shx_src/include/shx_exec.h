// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#ifndef __she_exec_h__
#define __she_exec_h__

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "shx_test.h"

#define SHE_TEST_COUNT 12
extern struct she_test_entry_t tests[SHE_TEST_COUNT];

int she_exec_function(int i, FILE *fp, void *testCtx);

#endif  // __she_exec_h__
