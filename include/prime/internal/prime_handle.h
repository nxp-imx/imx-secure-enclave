// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025-2026 NXP
 */

#ifndef PRIME_HANDLE_H
#define PRIME_HANDLE_H

/**
 * @defgroup prime_handle PRIME Handle Management
 * @ingroup prime_core
 * @brief Handle definitions and management for PRIME services
 *
 * This module provides handle type definitions used across PRIME services
 * for managing service sessions and resources.
 * @{
 */

#include <stdint.h>

/**
 * @brief Invalid/uninitialized handle value
 *
 * This value represents an invalid or uninitialized PRIME handle.
 * Used to indicate that no valid service handle has been assigned.
 */
#define PRIME_HANDLE_NONE		(0x0)

/**
 * @brief PRIME handle type definition
 *
 * Handle used to reference PRIME service sessions. Each opened service
 * is assigned a unique handle that must be used for all subsequent
 * operations on that service.
 */
typedef uint32_t prime_hdl_t;

/** @} */ /* end of prime_handle group */

#endif /* PRIME_HANDLE_H */
