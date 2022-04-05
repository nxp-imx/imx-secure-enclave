/*
 * Copyright 2022 NXP
 *
 * NXP Confidential.
 * This software is owned or controlled by NXP and may only be used strictly
 * in accordance with the applicable license terms.  By expressly accepting
 * such terms or by downloading, installing, activating and/or otherwise using
 * the software, you are agreeing that you have read, and that you agree to
 * comply with and are bound by, such license terms.  If you do not agree to be
 * bound by the applicable license terms, then you may not retain, install,
 * activate or otherwise use the software.
 */

#ifndef HSM_HANDLE_H
#define HSM_HANDLE_H

#define HSM_HANDLE_NONE		(0x0)

typedef uint32_t hsm_hdl_t;

struct hsm_session_hdl_s {
	struct plat_os_abs_hdl *phdl;
	uint32_t session_hdl;
	uint32_t mu_type;
};

struct hsm_service_hdl_s {
	struct hsm_session_hdl_s *session;
	uint32_t service_hdl;
};

#define HSM_MAX_SESSIONS	(8u)
#define HSM_MAX_SERVICES	(32u)

struct hsm_session_hdl_s *session_hdl_to_ptr(uint32_t hdl);
struct hsm_service_hdl_s *service_hdl_to_ptr(uint32_t hdl);
void delete_session(struct hsm_session_hdl_s *s_ptr);
void delete_service(struct hsm_service_hdl_s *s_ptr);
struct hsm_session_hdl_s *add_session(void);
struct hsm_service_hdl_s *add_service(struct hsm_session_hdl_s *session);
#endif
