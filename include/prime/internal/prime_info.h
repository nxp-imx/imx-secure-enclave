// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#ifndef PRIME_INFO_H
#define PRIME_INFO_H

/**
 * @defgroup prime_info PRIME Information Retrieval
 * @ingroup prime_core
 * @brief PRIME service information and capabilities
 *
 * This module provides functionality to retrieve PRIME service information
 * including firmware version and hardware capabilities.
 * @{
 */

#include "prime_handle.h"
#include "prime_utils.h"

/**
 * @brief PRIME service information structure
 *
 * Structure containing PRIME firmware version and hardware capability
 * information for an opened service session.
 */
typedef struct {
	uint8_t major;
	//!< Major version number of PRIME firmware
	uint8_t minor;
	//!< Minor version number of PRIME firmware
	uint8_t patch;
	//!< Patch version number of PRIME firmware
	uint32_t num_fifo_entries;
	//!< Number of FIFO entries supported by hardware (queue depth)
} prime_info_t;

/**
 * @brief Get PRIME service information
 *
 * Retrieves information about the PRIME service including firmware version
 * and hardware capabilities such as FIFO depth. This information can be
 * used to determine feature availability and optimize operation batching.
 *
 * @param[in] serv_hdl Handle to the PRIME service session
 * @param[out] prime_info Pointer to structure to be filled with service information
 *
 * @return PRIME_ERR_NONE on success
 * @return PRIME_ERR_INVALID_PARAM if parameters are invalid or NULL
 * @return PRIME_ERR_SERVICE_OPEN if service handle is invalid
 * @return PRIME_ERROR on other errors
 */
prime_err_t prime_get_info(prime_hdl_t serv_hdl, prime_info_t *prime_info);

/** @} */ /* end of prime_info group */

#endif
