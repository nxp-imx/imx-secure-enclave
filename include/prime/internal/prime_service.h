// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025-2026 NXP
 */

#ifndef PRIME_SERVICE_H
#define PRIME_SERVICE_H

/**
 * @defgroup prime_service PRIME Service Management
 * @ingroup prime_core
 * @brief PRIME service session lifecycle management
 *
 * This module provides functionality for opening and closing PRIME service
 * sessions, managing shared memory buffers, and configuring service types.
 * @{
 */

#include "prime_utils.h"
#include "prime_handle.h"
#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Maximum Key slots supported by Prime
 *
 * This value represents the maximum number of key slots supported 
 * by prime firmware i.e. maximum number of keys that can be loaded at one time.
 */
#define MAX_PRIME_KEY_SLOT_SUPPORTED	64

/**
 * @brief PRIME service types
 */
enum service_type {
	SERVICE_TYPE_NONE,
	//!< No service type specified
	SERVICE_TYPE_ALL = 7,
	//!< All available services (full functionality)
};

/**
 * @brief Structure containing all parameters required to open a PRIME service
 * session
 * \latexonly
 * \newpage
 * \endlatexonly
 */
typedef struct {
	prime_hdl_t service_hdl;
	//!< Service handle (output parameter, set by prime_open_service)
	enum service_type serv_type;
	//!< Service type to open (determines available functionality)
	uint64_t physical_addr;
	//!< Physical memory address for shared buffer (DMA accessible)
	//!< if NULL, the SE library will provide the physical address to the user
	//!< if not NULL, the SE library will program ATU(if 36 bit address),
	//!< User needs to set the physical address for both 36 bit and
	//!< 32 bit address range.
	uint64_t virtual_addr;
	//!< Virtual memory address for shared buffer (CPU accessible)
	//!< if physical address NULL, then SE library will provide the virtual address.
	uint32_t size;
	//!< Size of shared buffer in bytes
} open_service_args_t;

/**
 * @brief Open a PRIME service session
 *
 * Opens a new PRIME service session with the specified configuration.
 * Allocates resources and establishes communication with the PRIME
 * firmware through the Message Unit (MU). The shared memory buffer
 * is used for exchanging cryptographic operation data.
 *
 * @param[in,out] op_serv_args Pointer to service open arguments structure
 * @param[out] service_hdl Pointer to receive the allocated service handle
 *
 * @return PRIME_ERR_NONE on success
 * @return PRIME_ERR_INVALID_PARAM if parameters are invalid or NULL
 * @return PRIME_ERR_SERVICE_OPEN if service cannot be opened
 * @return PRIME_ERR_MEMORY_ALLOC if memory allocation fails
 * @return PRIME_ERROR on other errors
 */
prime_err_t prime_open_service(open_service_args_t *op_serv_args,
			       prime_hdl_t *service_hdl);

/**
 * @brief Close a PRIME service session
 *
 * Closes an opened PRIME service session and releases all associated
 * resources. All pending operations should be completed before closing
 * the service.
 *
 * @param[in] service_hdl Handle to the service session to close
 */
void prime_close_service(prime_hdl_t service_hdl);

/** @} */ /* end of prime_service group */

#endif
