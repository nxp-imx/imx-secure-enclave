/*
 * Copyright 2023 NXP
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

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_session.h"

#include "sab_process_msg.h"

static struct hsm_session_hdl_s hsm_sessions[HSM_MAX_SESSIONS] = {};
static struct hsm_service_hdl_s hsm_services[HSM_MAX_SERVICES] = {};

hsm_err_t hsm_close_session(hsm_hdl_t session_hdl)
{
	struct hsm_session_hdl_s *s_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t sab_err;
	uint32_t rsp_code;

	do {
		s_ptr = session_hdl_to_ptr(session_hdl);
		if (!s_ptr) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		sab_err = process_sab_msg(s_ptr->phdl,
					  s_ptr->mu_type,
					  SAB_SESSION_CLOSE_REQ,
					  MT_SAB_SESSION,
					  session_hdl,
					  NULL, &rsp_code);
		err = sab_rating_to_hsm_err(sab_err);

		if (err != HSM_NO_ERROR)
			se_err("HSM Error: SAB_SESSION_CLOSE_REQ [0x%x].\n", err);
		err = sab_rating_to_hsm_err(rsp_code);
		if (err != HSM_NO_ERROR)
			se_err("HSM RSP Error: SAB_SESSION_CLOSE_REQ [0x%x].\n", err);

		plat_os_abs_close_session(s_ptr->phdl);

		delete_session(s_ptr);

		memset(hsm_sessions, 0, HSM_MAX_SESSIONS);

		memset(hsm_services, 0, HSM_MAX_SERVICES);

		// TODO: should we close all associated services here ?
		// or sanity check that all services have been closed ?
	} while (false);

	return err;
}

hsm_err_t hsm_open_session(open_session_args_t *args, hsm_hdl_t *session_hdl)
{
	struct hsm_session_hdl_s *s_ptr = NULL;
	struct plat_mu_params mu_params;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t sab_err;
	uint8_t session_priority, operating_mode;
	uint32_t rsp_code;

	memset(hsm_sessions, 0, HSM_MAX_SESSIONS);
	memset(hsm_services, 0, HSM_MAX_SERVICES);

	do {
		if (!args || !session_hdl) {
			break;
		}

		/* sanity check on the input parameters. */
		session_priority = args->session_priority;
		operating_mode = args->operating_mode;
		if (session_priority != HSM_OPEN_SESSION_PRIORITY_LOW &&
		    session_priority != HSM_OPEN_SESSION_PRIORITY_HIGH) {
			break;
		}
		if ((operating_mode & HSM_OPEN_SESSION_RESERVED_MASK) != 0U)
			break;

		s_ptr = add_session();
		if (!s_ptr)
			break;

		if (plat_os_abs_has_v2x_hw() == 0U) {
			/* SECO only HW: low latency and high priority not supported. */
			operating_mode &= ~(uint8_t)HSM_OPEN_SESSION_LOW_LATENCY_MASK;
			session_priority = HSM_OPEN_SESSION_PRIORITY_LOW;
		}

		args = (open_session_args_t *)
			plat_os_abs_malloc((uint32_t)sizeof(open_session_args_t));
		if (!args)
			break;
		plat_os_abs_memset((uint8_t *)args, 0u, (uint32_t)sizeof(open_session_args_t));

		s_ptr->mu_type = mu_table[MU_CONFIG((session_priority), (operating_mode))];
		s_ptr->phdl = plat_os_abs_open_mu_channel(s_ptr->mu_type, &mu_params);
		if (!s_ptr->phdl)
			break;

		args->mu_id = mu_params.mu_id;
		args->interrupt_idx = mu_params.interrupt_idx;
		args->tz = mu_params.tz;
		args->did = mu_params.did;
		args->session_priority = session_priority;
		args->operating_mode = operating_mode;

		sab_err = process_sab_msg(s_ptr->phdl,
					  s_ptr->mu_type,
					  SAB_SESSION_OPEN_REQ,
					  MT_SAB_SESSION,
					  s_ptr->session_hdl,
					  args, &rsp_code);

		err = sab_rating_to_hsm_err(sab_err);
		if (err != HSM_NO_ERROR) {
			se_err("HSM Error: SAB_SESSION_OPEN_REQ [0x%x].\n", err);
			break;
		}
		err = sab_rating_to_hsm_err(rsp_code);
		if (err != HSM_NO_ERROR) {
			se_err("HSM RSP Error: SAB_SESSION_OPEN_REQ [0x%x].\n", err);
			break;
		}
		s_ptr->session_hdl = args->session_hdl;
		*session_hdl = s_ptr->session_hdl;
	} while (false);

	if (args) {
		plat_os_abs_free(args);
		args = NULL;
	}

	if (err != HSM_NO_ERROR) {
		if (s_ptr) {
			if (s_ptr->session_hdl != 0u) {
				(void)hsm_close_session(s_ptr->session_hdl);
			} else if (s_ptr->phdl) {
				plat_os_abs_close_session(s_ptr->phdl);
				delete_session(s_ptr);
			} else {
				delete_session(s_ptr);
			}
		}
		if (session_hdl)
			*session_hdl = 0u; /* force an invalid value.*/
	}

	return err;
}
