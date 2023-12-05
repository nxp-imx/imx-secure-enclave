// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <stdio.h>

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_butterfly.h"

#include "sab_process_msg.h"

hsm_err_t hsm_butterfly_key_expansion(hsm_hdl_t key_management_hdl,
				      op_butt_key_exp_args_t *args)
{
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;
	uint32_t lib_err;
	struct hsm_service_hdl_s *serv_ptr;

	do {
		if (!args || !(args->dest_key_identifier))
			break;

		serv_ptr = service_hdl_to_ptr(key_management_hdl);
		if (!serv_ptr) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		lib_err = process_sab_msg(serv_ptr->session->phdl,
					  serv_ptr->session->mu_type,
					  SAB_BUT_KEY_EXP_REQ,
					  MT_SAB_BUT,
					  (uint32_t)key_management_hdl,
					  args,
					  &rsp_code);

		err =  lib_err_to_hsm_err(lib_err);
		if (err != HSM_NO_ERROR)
			break;

		err = sab_rating_to_hsm_err(rsp_code, serv_ptr->session->phdl);
		if (err != HSM_NO_ERROR) {
			se_err("HSM RSP Error: SAB_BUT_KEY_EXP_REQ [0x%x].\n", err);
			break;
		}

	} while (false);

	return err;
}
