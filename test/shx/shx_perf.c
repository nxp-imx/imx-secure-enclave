// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "shx_perf.h"
#include "slt_log.h"

uint32_t print_perf(struct timespec *ts1, struct timespec *ts2, uint32_t nb_iter)
{
	uint64_t time_us;

	time_us = (uint64_t)(ts2->tv_sec - ts1->tv_sec) * 1000000u
		  + (ts2->tv_nsec - ts1->tv_nsec) / 1000;
	uint32_t time_operation_us = (uint32_t)(time_us / nb_iter);

	slt_print(SLT_DEBUG, "%d microseconds per operation (%d iterations).\n",
		  time_operation_us, nb_iter);

	return time_operation_us;
}
