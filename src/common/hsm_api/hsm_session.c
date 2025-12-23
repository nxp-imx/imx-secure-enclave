// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024, 2026 NXP
 */

#include <stdbool.h>
#include <stdio.h>

#include "common/se_lib_service.h"
#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_session.h"

#include "sab_process_msg.h"
#include "se_lib_serv_intern.h"

hsm_err_t hsm_close_session(hsm_hdl_t session_hdl)
{
	struct hsm_session_hdl_s *s_ptr;
	hsm_err_t err = HSM_UNKNOWN_HANDLE;
	uint32_t lib_err;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	do {
		if (!session_hdl)
			break;

		s_ptr = session_hdl_to_ptr(session_hdl);
		if (!s_ptr)
			break;

		lib_err = process_sab_msg(s_ptr->phdl,
					  s_ptr->mu_type,
					  SAB_SESSION_CLOSE_REQ,
					  MT_SAB_SESSION,
					  session_hdl,
					  NULL, &rsp_code);

		err = lib_err_to_hsm_err(lib_err);
		if (err != HSM_NO_ERROR)
			break;

		err = sab_rating_to_hsm_err(rsp_code, s_ptr->phdl);
		if (err != HSM_NO_ERROR)
			se_err("HSM RSP Error: SAB_SESSION_CLOSE_REQ [0x%x].\n", err);

		se_lib_close_service(s_ptr->se_lib_serv_hdl);

		delete_session(s_ptr);

		// TODO: should we close all associated services here ?
		// or sanity check that all services have been closed ?
	} while (false);

	return err;
}

hsm_err_t hsm_open_session(open_session_args_t *args, hsm_hdl_t *session_hdl)
{
	struct hsm_session_hdl_s *s_ptr = NULL;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t lib_err;
	uint8_t mu_type;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;
	struct se_lib_service_hdl_s *se_lib_s_ptr = NULL;
	open_se_lib_serv_args_t se_lib_serv_args;

	do {
		if (!args || !session_hdl) {
			break;
		}

		s_ptr = add_session();
		if (!s_ptr)
			break;

		mu_type = args->mu_type;
		se_lib_serv_args.mu_type = mu_type;
		se_lib_open_service(&se_lib_serv_args, &s_ptr->se_lib_serv_hdl);
		se_lib_s_ptr = se_lib_serv_hdl_to_ptr(s_ptr->se_lib_serv_hdl);

		if (!se_lib_s_ptr)
			break;

		s_ptr->mu_type = mu_type;
		s_ptr->phdl = se_lib_s_ptr->phdl;
		if (!s_ptr->phdl)
			break;

#ifndef PSA_COMPLIANT
		args->mu_id = se_lib_s_ptr->mu_params.mu_id;
		args->tz = se_lib_s_ptr->mu_params.tz;
		args->did = se_lib_s_ptr->mu_params.did;
#endif
		args->interrupt_idx = se_lib_s_ptr->mu_params.interrupt_idx;

		lib_err = process_sab_msg(s_ptr->phdl,
					  s_ptr->mu_type,
					  SAB_SESSION_OPEN_REQ,
					  MT_SAB_SESSION,
					  s_ptr->session_hdl,
					  args, &rsp_code);

		err = lib_err_to_hsm_err(lib_err);
		if (err != HSM_NO_ERROR)
			break;

		err = sab_rating_to_hsm_err(rsp_code, s_ptr->phdl);
		if (err != HSM_NO_ERROR) {
			se_err("HSM RSP Error: SAB_SESSION_OPEN_REQ [0x%x].\n", err);
			break;
		}
		s_ptr->session_hdl = args->session_hdl;
		*session_hdl = s_ptr->session_hdl;
	} while (false);

	if (err != HSM_NO_ERROR) {
		if (s_ptr) {
			if (s_ptr->session_hdl != 0u) {
				(void)hsm_close_session(s_ptr->session_hdl);
			} else if (s_ptr->phdl) {
				se_lib_close_service(s_ptr->se_lib_serv_hdl);
				delete_session(s_ptr);
			} else {
				delete_session(s_ptr);
			}
		}
		if (session_hdl)
			*session_hdl = 0u; /* force an invalid value.*/
	}

	//populate Global Info structure
	if (err == HSM_NO_ERROR)
		populate_global_info(*session_hdl);

	return err;
}
