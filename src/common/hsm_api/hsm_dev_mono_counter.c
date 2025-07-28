// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <stdbool.h>
#include <stdio.h>

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_dev_mono_counter.h"

#include "sab_process_msg.h"

hsm_err_t hsm_dev_mono_counter(hsm_hdl_t session_hdl, op_dev_mono_counter_args_t *args)
{
	struct hsm_session_hdl_s *sess_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t lib_err;
	uint32_t fuse_sum;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	do {
		if (!args)
			break;

		if (!session_hdl) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		sess_ptr = session_hdl_to_ptr(session_hdl);
		if (!sess_ptr) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		fuse_sum = args->ele_hsm_fuse_word +
			   args->v2x_hsm_fuse_word +
			   args->v2x_she_fuse_word;

		if (fuse_sum &&
		    (!args->ele_hsm_fuse_word ||
		    !args->v2x_hsm_fuse_word ||
		    !args->v2x_she_fuse_word) &&
		    !args->enforce_fuse) {
			se_err("Please set enforce_fuse if configuring fuse as 0\n");
			err = HSM_INVALID_PARAM;
			return err;
		}

		lib_err = process_sab_msg(sess_ptr->phdl,
					  sess_ptr->mu_type,
					  ROM_DEV_MONO_COUNTER_REQ,
					  MT_SAB_DEV_MONO_COUNTER,
					  HSM_HANDLE_NONE,
					  args, &rsp_code);

		args->warning = GET_RATING_CODE(rsp_code);
		err = lib_err_to_hsm_err(lib_err);
		if (err != HSM_NO_ERROR)
			break;

		err = sab_rating_to_hsm_err(rsp_code, sess_ptr->phdl);
		if (err != HSM_NO_ERROR)
			se_err("HSM RSP Error: SAB_DEV_MONO_COUNTER_REQ [0x%x].\n", err);

	} while (false);

	return err;
}
