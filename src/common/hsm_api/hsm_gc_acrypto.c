// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_gc_acrypto.h"

#include "sab_process_msg.h"

hsm_err_t hsm_gc_acrypto(hsm_hdl_t session_hdl, op_gc_acrypto_args_t *args)
{
	int32_t error;
	struct hsm_session_hdl_s *sess_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	do {
		if (!args)
			break;

		sess_ptr = session_hdl_to_ptr(session_hdl);
		if (!sess_ptr) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		error = process_sab_msg(sess_ptr->phdl,
					sess_ptr->mu_type,
					SAB_GC_ACRYPTO_REQ,
					MT_SAB_GC_ACRYPTO,
					(uint32_t)session_hdl,
					args, &rsp_code);

		err = sab_rating_to_hsm_err(error);

		if (err != HSM_NO_ERROR) {
			se_err("HSM Error: SAB_GC_ACRYPTO_REQ [0x%x].\n", err);
			break;
		}
		err = sab_rating_to_hsm_err(rsp_code);

		if (err == HSM_NO_ERROR &&
		    args->op_mode == HSM_GC_ACRYPTO_OP_MODE_SIGN_VER &&
		    args->verification_status != HSM_GC_ACRYPTO_VERIFICATION_SUCCESS)
			err = HSM_SIGNATURE_INVALID;

		if (err != HSM_NO_ERROR)
			se_err("HSM RSP Error: SAB_GC_ACRYPTO_REQ [0x%x].\n", err);

	} while (false);

	return err;
}
