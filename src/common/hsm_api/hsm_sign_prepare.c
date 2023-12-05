// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <stdio.h>

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_sign_prepare.h"

#include "sab_process_msg.h"

hsm_err_t hsm_prepare_signature(hsm_hdl_t signature_gen_hdl,
				op_prepare_sign_args_t *args)
{
	uint32_t error;
	struct hsm_service_hdl_s *serv_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	do {
		if (!args)
			break;

		if (!signature_gen_hdl) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		serv_ptr = service_hdl_to_ptr(signature_gen_hdl);
		if (!serv_ptr) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		error = process_sab_msg(serv_ptr->session->phdl,
					serv_ptr->session->mu_type,
					SAB_SIGNATURE_PREPARE_REQ,
					MT_SAB_SIGN_PREPARE,
					(uint32_t)signature_gen_hdl,
					args, &rsp_code);

		err = sab_rating_to_hsm_err(error, serv_ptr->session->phdl);
		if (err != HSM_NO_ERROR) {
			se_err("HSM Error: SAB_SIGNATURE_PREPARE_REQ [0x%x].\n",
			       err);
			break;
		}

		err = sab_rating_to_hsm_err(rsp_code, serv_ptr->session->phdl);
		if (err != HSM_NO_ERROR)
			se_err("HSM RSP Error: SAB_SIGNATURE_PREPARE_REQ [0x%x].\n",
			       err);

	} while (false);

	return err;
}
