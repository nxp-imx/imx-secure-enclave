// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include <stdbool.h>
#include <stdio.h>

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_dev_attest.h"

#include "sab_process_msg.h"

static uint8_t validate_input(op_dev_attest_args_t *args)
{
	uint8_t ret = 0;

	if (hsm_get_dev_attest_api_ver() == HSM_API_VERSION_1)
		ret = args->nounce_sz != DEV_ATTEST_NOUNCE_SIZE_V1;
	else
		ret = args->nounce_sz != DEV_ATTEST_NOUNCE_SIZE_V2;

	return ret;
}

hsm_err_t hsm_dev_attest(hsm_hdl_t session_hdl, op_dev_attest_args_t *args)
{
	struct hsm_session_hdl_s *sess_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t error;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	do {
		if (!args)
			break;

		if (validate_input(args)) {
			se_err("HSM Error: Invalid parameter values\n");
			break;
		}

		if (!session_hdl) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

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
			se_err("HSM Error: SAB_DEV_ATTEST_REQ [0x%x].\n", err);
			break;
		}
		err = sab_rating_to_hsm_err(rsp_code);
		if (err != HSM_NO_ERROR) {
			se_err("HSM RSP Error: SAB_DEV_ATTEST_REQ [0x%x].\n",
				err);
		}

	} while (false);

	return err;
}
