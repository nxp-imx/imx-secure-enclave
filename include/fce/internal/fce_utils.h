// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#ifndef FCE_UTILS_H
#define FCE_UTILS_H

#include "stdint.h"

/*
 * Error codes returned by FCE functions.
 */
typedef enum {
	FCE_NO_ERROR,
	FCE_ERROR,
} fce_err_t;

struct buf {
	uint8_t *virt_addr;
	uint32_t phys_addr;
	uint32_t len;
};

#endif
