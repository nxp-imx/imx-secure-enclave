/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025 NXP
 */

#ifndef _V2X_FCE_TIME_H_
#define _V2X_FCE_TIME_H_

#include <time.h>

#define USEC_IN_SEC	1000000L
#define NSEC_IN_USEC	1000L

static inline unsigned long get_time_in_us(void)
{
	struct timespec ts = {0, 0};

	clock_gettime(CLOCK_MONOTONIC_RAW, &ts);

	return ((uint64_t)ts.tv_sec * USEC_IN_SEC) + (ts.tv_nsec / NSEC_IN_USEC);
}

static inline uint32_t timeout_expire(unsigned long time, unsigned long timeout)
{
	return (time > timeout ? 1 : 0);
}

/*
 * read_and_timeout_check - read addr until a condition is met or a timeout occurs
 * @addr: address to read from
 * @val: Variable to read the value into
 * @cond: Break condition (involving @val)
 * @timeout_val: Timeout in us, 0 means never timeout
 *
 * Returns 0 on success and -ETIMEDOUT upon a timeout. In either
 * case, the last read value at @addr is stored in @val.
 */
#define read_and_timeout_check(addr, val, cond, timeout_val)	\
({ \
	unsigned long timeout_us = get_time_in_us() + (timeout_val); \
	for (;;) { \
		(val) = (*(volatile unsigned int *)(addr)); \
		if (cond) \
			break; \
		if (timeout_val && timeout_expire(get_time_in_us(), timeout_us)) { \
			(val) = (*(volatile unsigned int *)(addr)); \
			break; \
		} \
	} \
	(cond) ? 0 : -ETIMEDOUT; \
})

#endif /* _V2X_FCE_TIME_H_ */
