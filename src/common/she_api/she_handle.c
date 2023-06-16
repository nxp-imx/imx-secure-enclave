// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "internal/she_handle.h"

struct she_hdl_s she_sessions[SHE_MAX_SESSIONS] = {'\0'};

struct she_hdl_s *she_session_hdl_to_ptr(uint32_t hdl)
{
	uint32_t i;
	struct she_hdl_s *ret;

	ret = NULL;

	if (hdl == 0)
		return ret;

	for (i = 0u; i < SHE_MAX_SESSIONS; i++) {
		printf("hdl 0x%x she_sessions[i].session_handle [0x%p] [%d] : 0x%x\n",
		       hdl, &she_sessions[i], i, she_sessions[i].session_handle);
		if (hdl == she_sessions[i].session_handle) {
			if (she_sessions[i].phdl)
				ret = &she_sessions[i];
			break;
		}
	}
	return ret;
}

struct she_hdl_s *add_she_session(void)
{
	uint32_t i;
	struct she_hdl_s *s_ptr = NULL;

	for (i = 0u; i < SHE_MAX_SESSIONS; i++) {
		if (!she_sessions[i].phdl && !she_sessions[i].session_handle) {
			/* Found an empty slot. */
			s_ptr = &she_sessions[i];
			break;
		}
	}
	printf("%s %d , 0x%p\n", __func__, i, s_ptr);
	return s_ptr;
}

void delete_she_session(struct she_hdl_s *s_ptr)
{
	if (s_ptr) {
		s_ptr->phdl = NULL;
		s_ptr->session_handle = 0u;
	}
}
