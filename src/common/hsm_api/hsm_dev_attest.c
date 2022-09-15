/*
 * Copyright 2022 NXP
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

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_dev_attest.h"

#include "sab_process_msg.h"

hsm_err_t hsm_dev_attest(hsm_hdl_t session_hdl, op_dev_attest_args_t *args)
{
	struct hsm_session_hdl_s *sess_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t error;
	uint32_t rsp_code;

	do {
		sess_ptr = session_hdl_to_ptr(session_hdl);
		if (sess_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		error = process_sab_msg(sess_ptr->phdl,
					sess_ptr->mu_type,
					ROM_DEV_ATTEST_REQ,
					MT_SAB_DEV_ATTEST,
					HSM_HANDLE_NONE,
					args, &rsp_code);

		err = sab_rating_to_hsm_err(error);

		if (err != HSM_NO_ERROR) {
			printf("HSM Error: SAB_DEV_ATTEST_REQ [0x%x].\n", err);
			break;
		}
		err = sab_rating_to_hsm_err(rsp_code);
		if (err != HSM_NO_ERROR) {
			printf("HSM RSP Error: SAB_DEV_ATTEST_REQ [0x%x].\n",
				err);
		}

	} while (false);

	return err;
}
