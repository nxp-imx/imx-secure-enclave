// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025-2026 NXP
 */

#ifndef PRIME_UTILS_H
#define PRIME_UTILS_H

#include <stdint.h>

/**
 * Prime error codes
 */
typedef enum {
	PRIME_ERR_NONE = 0,
	PRIME_ERR_INVALID_PARAM = 1,
	PRIME_ERR_MEMORY_ALLOC = 2,
	PRIME_ERR_SERVICE_OPEN = 3,
	PRIME_ERR_SERVICE_CLOSE = 4,
	PRIME_ERROR = 5,
} prime_err_t;

struct buf {
	uint8_t *virt_addr;
	uint64_t phys_addr;
	uint32_t len;
};

#endif
