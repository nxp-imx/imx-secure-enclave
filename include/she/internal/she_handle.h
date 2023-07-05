// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SHE_HANDLE_H
#define SHE_HANDLE_H

#include <stdint.h>

/**
 *  @defgroup group1 Session
 *  @{
 */

/**
 * Handle not available
 */
#define SHE_HANDLE_NONE		(0x0)

/**
 * Maximum sessions supported
 */
#define SHE_MAX_SESSIONS        (16u)

/**
 *  Define the SHE handle type
 */
typedef uint32_t she_hdl_t;

/**
 * Structure describing the session handle members
 */
struct she_hdl_s {
	struct plat_os_abs_hdl *phdl;
	//!< Pointer to OS device node.
	uint32_t session_handle;
	//!< Session handle.
	uint32_t key_store_handle;
	//!< handle to access key store
	uint32_t cipher_handle;
	//!< handle to access cipher services
	uint32_t rng_handle;
	//!< RNG handle
	uint32_t utils_handle;
	//!< handle to access utility
	uint32_t mu_type;
	//!< Session MU type.
};

/**
 * Returns pointer to the session handle\n
 *
 * \param hdl identifying the session handle.
 *
 * \return pointer to the session handle.
 */
struct she_hdl_s *she_session_hdl_to_ptr(uint32_t hdl);

/**
 * Delete the session\n
 *
 * \param s_ptr pointer identifying the session.
 *
 */
void delete_she_session(struct she_hdl_s *s_ptr);

/**
 *  Add the session\n
 *
 * \return pointer to the session.
 */
struct she_hdl_s *add_she_session(void);

/** @} end of session group */
#endif
