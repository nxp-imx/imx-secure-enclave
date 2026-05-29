// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#ifndef V2X_VERSION_H
#define V2X_VERSION_H

/**
 * @defgroup v2x_version V2X Version Information
 * @ingroup prime_core
 * @brief V2X software version retrieval
 *
 * This module provides functionality to retrieve V2X software version
 * information including major, minor, patch numbers and commit ID.
 * @{
 */

#include "prime_utils.h"

/**
 * @brief V2X version information structure
 *
 * Structure containing version information for the V2X software stack.
 * Follows semantic versioning (major.minor.patch) with additional
 * commit identifier.
 */
typedef struct {
	uint8_t major;
	//!< Major version number (incremented for incompatible API changes)
	uint8_t minor;
	//!< Minor version number (incremented for backward-compatible functionality)
	uint8_t patch;
	//!< Patch version number (incremented for backward-compatible bug fixes)
	uint32_t commit_id;
	//!< Git commit identifier or build number
} v2x_version_t;

/**
 * @brief Get V2X software version information
 *
 * Retrieves the current V2X software version including major, minor,
 * patch numbers and commit identifier.
 *
 * @param[out] args Pointer to version structure to be filled with version information
 *
 * @return PRIME_ERR_NONE on success
 * @return PRIME_ERR_INVALID_PARAM if args is NULL
 * @return PRIME_ERROR on other errors
 */
prime_err_t get_v2x_version(v2x_version_t *args);

/** @} */ /* end of v2x_version group */

#endif
