// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#ifndef __SHX_PERF_H__
#define __SHX_PERF_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

uint32_t print_perf(struct timespec *ts1, struct timespec *ts2, uint32_t nb_iter);

#endif
