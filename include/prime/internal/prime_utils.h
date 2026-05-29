// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025-2026 NXP
 */

#ifndef PRIME_UTILS_H
#define PRIME_UTILS_H

/**
 * @defgroup prime_utils PRIME Utility Definitions
 * @ingroup prime_core
 * @brief Common utility types and error codes for PRIME API
 *
 * This module provides common definitions used across the PRIME API
 * including error codes and buffer structures.
 * @{
 */

#include <stdint.h>

/**
 * @brief PRIME error codes
 *
 * Enumeration of error codes returned by PRIME API functions.
 * All PRIME functions return these standardized error codes to
 * indicate success or failure reasons.
 */
typedef enum {
	PRIME_ERR_NONE = 0,
	//!< Operation completed successfully
	PRIME_ERR_INVALID_PARAM = 1,
	//!< Invalid parameter provided (NULL pointer, out of range value, etc.)
	PRIME_ERR_MEMORY_ALLOC = 2,
	//!< Memory allocation failed
	PRIME_ERR_SERVICE_OPEN = 3,
	//!< Service open operation failed
	PRIME_ERR_SERVICE_CLOSE = 4,
	//!< Service close operation failed
	PRIME_ERROR = 5,
	//!< Generic error (unspecified failure)
} prime_err_t;

/**
 * @brief Buffer descriptor structure
 *
 * Structure describing a memory buffer with both virtual and physical
 * addresses. Used for DMA operations where hardware needs physical
 * addresses and software needs virtual addresses.
 */
struct buf {
	uint8_t *virt_addr;
	//!< Virtual address of buffer (CPU accessible)
	uint64_t phys_addr;
	//!< Physical address of buffer (DMA/hardware accessible)
	//!< This address needs to be 64 byte aligned because
	//!< Cache-line alignment is 64 bytes
	uint32_t len;
	//!< Length of buffer in bytes
};

/** @} */ /* end of prime_utils group */

#endif
