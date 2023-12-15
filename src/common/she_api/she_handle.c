// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "plat_utils.h"
#include "internal/she_handle.h"

static struct she_session_hdl_s she_sessions[SHE_MAX_SESSIONS] = {'\0'};
static struct she_service_hdl_s she_services[SHE_MAX_SERVICES] = {'\0'};

struct she_session_hdl_s *she_session_hdl_to_ptr(uint32_t hdl)
{
	uint32_t i;
	struct she_session_hdl_s *ret;

	ret = NULL;

	if (hdl == 0)
		return ret;

	for (i = 0u; i < SHE_MAX_SESSIONS; i++) {
		se_info("hdl 0x%x she_sessions[i].session_handle [0x%p] [%d] : 0x%x\n",
			hdl, &she_sessions[i], i, she_sessions[i].session_hdl);
		if (hdl == she_sessions[i].session_hdl) {
			if (she_sessions[i].phdl)
				ret = &she_sessions[i];
			break;
		}
	}
	return ret;
}

struct she_session_hdl_s *add_she_session(void)
{
	uint32_t i;
	struct she_session_hdl_s *s_ptr = NULL;

	for (i = 0u; i < SHE_MAX_SESSIONS; i++) {
		if (!she_sessions[i].phdl && !she_sessions[i].session_hdl) {
			/* Found an empty slot. */
			s_ptr = &she_sessions[i];
			break;
		}
	}
	return s_ptr;
}

void delete_she_session(struct she_session_hdl_s *s_ptr)
{
	if (s_ptr) {
		s_ptr->phdl = NULL;
		s_ptr->session_hdl = 0u;
	}
}

struct she_service_hdl_s *she_service_hdl_to_ptr(uint32_t hdl)
{
	uint32_t i;
	struct she_service_hdl_s *ret;

	ret = NULL;
	for (i = 0u; i < SHE_MAX_SERVICES; i++) {
		if (hdl == she_services[i].service_hdl) {
			if (she_services[i].session) {
				ret = &she_services[i];
				break;
			}
		}
	}
	return ret;
}

struct she_service_hdl_s *add_she_service(struct she_session_hdl_s *session)
{
	uint32_t i;
	struct she_service_hdl_s *s_ptr = NULL;

	for (i = 0u; i < SHE_MAX_SERVICES; i++) {
		if (!she_services[i].session &&
		    she_services[i].service_hdl == 0u) {
			/* Found an empty slot. */
			s_ptr = &she_services[i];
			s_ptr->session = session;
			break;
		}
	}
	return s_ptr;
}

void delete_she_service(struct she_service_hdl_s *s_ptr)
{
	if (s_ptr) {
		s_ptr->session = NULL;
		s_ptr->service_hdl = 0u;
	}
}
