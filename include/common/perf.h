// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#ifndef PERF_H
#define PERF_H

#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#define PERF_SUCCESS 0
#define PERF_FAILURE 1

/**
 * Structure detailing the members to store timestamps from kernel
 */
struct time_frame {
	struct timespec t_start;
	//!< Start timer.
	struct timespec t_end;
	//!< End timer.
};

/**
 * Get start and end timer value in kernel to be used to calculate performance
 * for a crypto operation.
 *
 * \param session_hdl identifying the session.
 * \param perf_time pointer to the structure to get populated with start and
    end timers from kernel.
 */
uint32_t get_perf_timer(uint32_t session_hdl, struct time_frame *perf_time);

#endif
