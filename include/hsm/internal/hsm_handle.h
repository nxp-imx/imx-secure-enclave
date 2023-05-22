// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#ifndef HSM_HANDLE_H
#define HSM_HANDLE_H

#include <stdint.h>

#define HSM_HANDLE_NONE		(0x0)

/**
 *  @defgroup group1 Session
 *  @{
 */

/**
 *  Define the HSM handle type
 */
typedef uint32_t hsm_hdl_t;

/**
 * Structure describing the session handle members
 */
struct hsm_session_hdl_s {
	struct plat_os_abs_hdl *phdl;
		//!< Pointer to OS device node.
	uint32_t session_hdl;
		//!< Session handle.
	uint32_t mu_type;
		//!< Session MU type.
};

/**
 * Structure describing the service handle members
 */
struct hsm_service_hdl_s {
	struct hsm_session_hdl_s *session;
		//!< Pointer to session handle.
	uint32_t service_hdl;
		//!< Service handle.
};

#define HSM_MAX_SESSIONS	(8u)
//!< Maximum sessions supported.
#define HSM_MAX_SERVICES	(32u)
//!< Maximum services supported.

/**
 * Returns pointer to the session handle\n
 *
 * \param hdl identifying the session handle.
 *
 * \return pointer to the session handle.
 */
struct hsm_session_hdl_s *session_hdl_to_ptr(uint32_t hdl);

/**
 * Returns pointer to the service handle\n
 *
 * \param hdl identifying the session handle.
 *
 * \return pointer to the service handle.
 */
struct hsm_service_hdl_s *service_hdl_to_ptr(uint32_t hdl);

/**
 * Delete the session\n
 *
 * \param s_ptr pointer identifying the session.
 *
 */
void delete_session(struct hsm_session_hdl_s *s_ptr);

/**
 * Delete the service\n
 *
 * \param s_ptr pointer identifying the service.
 *
 */
void delete_service(struct hsm_service_hdl_s *s_ptr);

/**
 *  Add the session\n
 *
 * \return pointer to the session.
 */
struct hsm_session_hdl_s *add_session(void);

/**
 * Add the service\n
 *
 * \return pointer to the service.
 */
struct hsm_service_hdl_s *add_service(struct hsm_session_hdl_s *session);
/** @} end of session group */
#endif
