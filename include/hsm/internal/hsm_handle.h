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
typedef uint32_t hsm_hdl_t;

struct hsm_session_hdl_s {
	struct plat_os_abs_hdl *phdl;
		//!< Pointer to OS device node.
	uint32_t session_hdl;
		//!< Session handle.
	uint32_t mu_type;
		//!< Session MU type.
};

struct hsm_service_hdl_s {
	struct hsm_session_hdl_s *session;
		//!< Pointer to session handle.
	uint32_t service_hdl;
		//!< Service handle.
};

#define HSM_MAX_SESSIONS	(8u)
#define HSM_MAX_SERVICES	(32u)

struct hsm_session_hdl_s *session_hdl_to_ptr(uint32_t hdl);
struct hsm_service_hdl_s *service_hdl_to_ptr(uint32_t hdl);
void delete_session(struct hsm_session_hdl_s *s_ptr);
void delete_service(struct hsm_service_hdl_s *s_ptr);
struct hsm_session_hdl_s *add_session(void);
struct hsm_service_hdl_s *add_service(struct hsm_session_hdl_s *session);
/** @} end of session group */
#endif
