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

#define SHE_MAX_SESSIONS	(8u)
//!< Maximum sessions supported.

#define SHE_MAX_SERVICES	(32u)
//!< Maximum services supported.

#define MAX_KEY_STORE_SESSIONS	(5u)
//!< Maximum Key store sessions supported.

/**
 * Structure describing the session handle members
 */
struct she_session_hdl_s {
	struct plat_os_abs_hdl *phdl;
	//!< Pointer to OS device node.
	uint32_t session_hdl;
	//!< Session handle.
	uint32_t mu_type;
	//!< Session MU type.
	uint32_t last_rating;
	//!< last error code returned by command.
};

/**
 * Structure describing the service handle members
 */
struct she_service_hdl_s {
	struct she_session_hdl_s *session;
	//!< Pointer to session handle.
	uint32_t service_hdl;
	//!< Service handle.
};

/**
 *  Define the SHE handle type
 */
typedef uint32_t she_hdl_t;

/**
 * Returns pointer to the session handle\n
 *
 * \param hdl identifying the session handle.
 *
 * \return pointer to the session handle.
 */
struct she_session_hdl_s *she_session_hdl_to_ptr(uint32_t hdl);

/**
 * Delete the session\n
 *
 * \param s_ptr pointer identifying the session.
 *
 */
void delete_she_session(struct she_session_hdl_s *s_ptr);

/**
 *  Add the session\n
 *
 * \return pointer to the session.
 */
struct she_session_hdl_s *add_she_session(void);

/**
 * Returns pointer to the service handle\n
 *
 * \param hdl identifying the session handle.
 *
 * \return pointer to the service handle.
 */
struct she_service_hdl_s *she_service_hdl_to_ptr(uint32_t hdl);

/**
 * Delete the service\n
 *
 * \param s_ptr pointer identifying the service.
 *
 */
void delete_she_service(struct she_service_hdl_s *s_ptr);

/**
 * Add the service\n
 *
 * \return pointer to the service.
 */
struct she_service_hdl_s *add_she_service(struct she_session_hdl_s *session);

/** @} end of session group */
#endif
