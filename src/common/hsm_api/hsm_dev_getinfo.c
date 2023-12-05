// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include <stdbool.h>
#include <stdio.h>

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_dev_getinfo.h"

#include "sab_process_msg.h"

hsm_err_t hsm_dev_getinfo(hsm_hdl_t session_hdl, op_dev_getinfo_args_t *args)
{
	struct hsm_session_hdl_s *sess_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t lib_err;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	do {
		if (!args)
			break;

		if (!session_hdl) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		sess_ptr = session_hdl_to_ptr(session_hdl);
		if (sess_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		lib_err = process_sab_msg(sess_ptr->phdl,
					  sess_ptr->mu_type,
					  ROM_DEV_GETINFO_REQ,
					  MT_SAB_DEV_GETINFO,
					  HSM_HANDLE_NONE,
					  args, &rsp_code);

		err = lib_err_to_hsm_err(lib_err);
		if (err != HSM_NO_ERROR)
			break;

		err = sab_rating_to_hsm_err(rsp_code, sess_ptr->phdl);
		if (err != HSM_NO_ERROR) {
			se_err("HSM RSP Error: SAB_DEV_GETINFO_REQ [0x%x].\n",
				err);
		}

	} while (false);

	return err;
}

hsm_key_lifecycle_t hsm_get_lc_from_lmda(hsm_lmda_val_t lmda_val)
{
	hsm_key_lifecycle_t ret = HSM_KEY_LIFECYCLE_INVALID;

	switch (lmda_val)  {
	case HSM_LMDA_OEM_OPEN:
		ret = HSM_KEY_LIFECYCLE_OPEN;
		break;

	case HSM_LMDA_OEM_CLOSED:
		ret = HSM_KEY_LIFECYCLE_CLOSED;
		break;

	case HSM_LMDA_OEM_LOCKED:
		ret = HSM_KEY_LIFECYCLE_CLOSED_LOCKED;
		break;

	default:
		break;
	}

	return ret;
}
