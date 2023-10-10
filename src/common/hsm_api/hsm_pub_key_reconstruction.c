// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <stdio.h>

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_pub_key_reconstruction.h"

#include "sab_process_msg.h"

hsm_err_t hsm_pub_key_reconstruction(hsm_hdl_t session_hdl,
				     op_pub_key_rec_args_t *args)
{
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;
	uint32_t lib_err;
	struct hsm_session_hdl_s *sess_ptr;

	do {
		if (!args || !session_hdl)
			break;

		sess_ptr = session_hdl_to_ptr(session_hdl);
		if (!sess_ptr) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		lib_err = process_sab_msg(sess_ptr->phdl,
					  sess_ptr->mu_type,
					  SAB_PUB_KEY_RECONSTRUCTION_REQ,
					  MT_SAB_PUB_KEY_RECONSTRUCTION,
					  (uint32_t)session_hdl,
					  args,
					  &rsp_code);

		err = lib_err_to_hsm_err(lib_err);
		if (err != HSM_NO_ERROR)
			break;

		err = sab_rating_to_hsm_err(rsp_code);
		if (err != HSM_NO_ERROR) {
			se_err("HSM RSP Error: SAB_PUB_KEY_RECONSTRUCTION [0x%x]\n", err);
			break;
		}

	} while (false);

	return err;
}