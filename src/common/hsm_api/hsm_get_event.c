// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025-2026 NXP
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "internal/hsm_utils.h"
#include "internal/hsm_handle.h"
#include "internal/hsm_get_event.h"

#include "sab_process_msg.h"
#include "se_lib_serv_intern.h"

#include "plat_utils.h"
#include "plat_os_abs.h"

hsm_err_t hsm_get_event(hsm_hdl_t session_hdl, op_get_event_msg_args_t *args)
{
	struct se_lib_service_hdl_s *se_lib_serv_ptr;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;
	struct hsm_session_hdl_s *sess_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;
	struct plat_os_abs_hdl *phdl;
	uint32_t mu_type;
	uint32_t lib_err;

	do {
		if (!args)
			break;

		sess_ptr = session_hdl_to_ptr(session_hdl);
		if (!sess_ptr) {
			err = HSM_UNKNOWN_HANDLE;
			se_lib_serv_ptr = se_lib_serv_hdl_to_ptr(session_hdl);
			if (!se_lib_serv_ptr || !se_lib_serv_ptr->phdl)
				break;
			phdl = se_lib_serv_ptr->phdl;
			mu_type = se_lib_serv_ptr->mu_type;
		} else {
			phdl = sess_ptr->phdl;
			mu_type = sess_ptr->mu_type;
		}

		lib_err = process_sab_msg(phdl,
					  mu_type,
					  ROM_DEV_GET_EVENT,
					  MT_SAB_GET_EVENT,
					  HSM_HANDLE_NONE,
					  args, &rsp_code);

		err = lib_err_to_hsm_err(lib_err);

		if (err != HSM_NO_ERROR)
			break;

		err = sab_rating_to_hsm_err(rsp_code, phdl);

		if (err != HSM_NO_ERROR)
			se_err("HSM RSP Error: %s [0x%x].\n",
			       "DEVICE_GET_EVENT", err);

	} while (false);

	return err;
}
