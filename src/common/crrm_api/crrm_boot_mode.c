// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <stdbool.h>
#include <stdio.h>

#include "internal/hsm_utils.h"
#include "internal/crrm_boot_mode.h"

#include "sab_process_msg.h"

crrm_err_t crrm_get_boot_mode(crrm_hdl_t crrm_hdl, op_get_boot_mode_args_t *args)
{
	crrm_err_t err = HSM_GENERAL_ERROR;
	struct hsm_session_hdl_s *sess_ptr;
	uint32_t error;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	do {
		if (!crrm_hdl)
			break;

		if (!args)
			break;

		sess_ptr = session_hdl_to_ptr(crrm_hdl);
		if (!sess_ptr) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		error = process_sab_msg(sess_ptr->phdl,
					sess_ptr->mu_type,
					SAB_CRRM_GET_BOOT_MODE_REQ,
					MT_SAB_BOOT_MODE,
					crrm_hdl,
					args, &rsp_code);

		err =  lib_err_to_hsm_err(error);
		if (err != HSM_NO_ERROR)
			break;

		err = sab_rating_to_hsm_err(rsp_code, sess_ptr->phdl);
		if (err != HSM_NO_ERROR) {
			se_err("CRRM RSP Error: SAB_CRRM_GET_BOOT_MODE_REQ [0x%x].\n",
			       err);
		}

	} while (false);

	return err;
}

crrm_err_t crrm_set_boot_mode(crrm_hdl_t crrm_hdl, op_set_boot_mode_args_t *args)
{
	crrm_err_t err = HSM_GENERAL_ERROR;
	struct hsm_session_hdl_s *sess_ptr;
	uint32_t error;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	do {
		if (!crrm_hdl)
			break;

		if (!args)
			break;

		sess_ptr = session_hdl_to_ptr(crrm_hdl);
		if (!sess_ptr) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		error = process_sab_msg(sess_ptr->phdl,
					sess_ptr->mu_type,
					SAB_CRRM_SET_BOOT_MODE_REQ,
					MT_SAB_BOOT_MODE,
					crrm_hdl,
					args, &rsp_code);

		err =  lib_err_to_hsm_err(error);
		if (err != HSM_NO_ERROR)
			break;

		err = sab_rating_to_hsm_err(rsp_code, sess_ptr->phdl);
		if (err != HSM_NO_ERROR) {
			se_err("CRRM RSP Error: SAB_CRRM_SET_BOOT_MODE_REQ [0x%x].\n",
			       err);
		}

	} while (false);

	return err;
}
