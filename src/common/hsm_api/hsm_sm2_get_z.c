// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_sm2_get_z.h"

#include "sab_process_msg.h"

#include "plat_utils.h"
#include "plat_os_abs.h"

hsm_err_t hsm_sm2_get_z(hsm_hdl_t session_hdl, op_sm2_get_z_args_t *args)
{
	uint32_t error;
	struct hsm_session_hdl_s *sess_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	do {
		if (!args || !session_hdl)
			break;

		sess_ptr = session_hdl_to_ptr(session_hdl);
		if (!sess_ptr) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		error = process_sab_msg(sess_ptr->phdl,
					sess_ptr->mu_type,
					SAB_SM2_GET_Z_REQ,
					MT_SAB_SM2_GET_Z,
					(uint32_t)session_hdl,
					args, &rsp_code);

		err = sab_rating_to_hsm_err(error, sess_ptr->phdl);
		if (err != HSM_NO_ERROR) {
			se_err("HSM Error: SAB_SM2_GET_Z [0x%x].\n", err);
			break;
		}

		err = sab_rating_to_hsm_err(rsp_code, sess_ptr->phdl);
		if (err != HSM_NO_ERROR)
			se_err("HSM RSP Error: SAB_SM2_GET_Z [0x%x].\n", err);

	} while (false);

	return err;
}
