// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#ifndef PRIME_UTILS_H
#define PRIME_UTILS_H

#include "stdint.h"

/*
 * Error codes returned by PRIME functions.
 */
typedef enum {
	PRIME_NO_ERROR,
	PRIME_ERROR,
} prime_err_t;

struct buf {
	uint8_t *virt_addr;
	uint32_t phys_addr;
	uint32_t len;
};

#endif
