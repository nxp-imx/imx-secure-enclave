// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include "internal/hsm_utils.h"
#include "internal/hsm_handle.h"
#include "internal/hsm_blob_unblob.h"

#include "sab_process_msg.h"

#include "plat_utils.h"
#include "plat_os_abs.h"

hsm_err_t hsm_blob_unblob(hsm_hdl_t session_hdl, op_blob_unblob_msg_args_t *args)
{
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;
	struct hsm_session_hdl_s *sess_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t lib_err;

	do {
		if (!args)
			break;

		sess_ptr = session_hdl_to_ptr(session_hdl);
		if (!sess_ptr) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		lib_err = process_sab_msg(sess_ptr->phdl,
					  sess_ptr->mu_type,
					  ROM_BLOB_UNBLOB_REQ,
					  MT_SAB_BLOB_UNBLOB,
					  HSM_HANDLE_NONE,
					  args, &rsp_code);

		err = lib_err_to_hsm_err(lib_err);

		if (err != HSM_NO_ERROR)
			break;

		err = sab_rating_to_hsm_err(rsp_code, sess_ptr->phdl);

		if (err != HSM_NO_ERROR)
			se_err("HSM RSP Error: %s [0x%x].\n",
			       "ELE_BLOB_UNBLOB_REQ", err);

	} while (false);

	return err;
}
