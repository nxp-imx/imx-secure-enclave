// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <stdio.h>

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_root_kek_export.h"

#include "plat_utils.h"
#include "sab_process_msg.h"

hsm_err_t hsm_export_root_key_encryption_key(hsm_hdl_t session_hdl,
					     op_export_root_kek_args_t *args)
{
	struct hsm_session_hdl_s *sess_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;
	uint32_t lib_err;

	do {
		if (!args || !session_hdl)
			break;

		sess_ptr = session_hdl_to_ptr(session_hdl);
		if (!sess_ptr) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		/* Send the signed message to platform if provided here. */
		if (args->signed_message) {
			lib_err = plat_os_abs_signed_message_v2(sess_ptr->phdl,
								args->signed_message,
								args->signed_msg_size);

			err = plat_err_to_hsm_err(SAB_ROOT_KEK_EXPORT_REQ,
						  lib_err,
						  HSM_PREPARE);
			if (err != HSM_NO_ERROR)
				break;
		}

		lib_err = process_sab_msg(sess_ptr->phdl,
					  sess_ptr->mu_type,
					  SAB_ROOT_KEK_EXPORT_REQ,
					  MT_SAB_ROOT_KEK_EXPORT,
					  session_hdl,
					  args, &rsp_code);

		err = lib_err_to_hsm_err(lib_err);
		if (err != HSM_NO_ERROR)
			break;

		err = sab_rating_to_hsm_err(rsp_code);

		if (err != HSM_NO_ERROR) {
			se_err("HSM RSP Error: SAB_ROOT_KEK_EXPORT_REQ [0x%x].\n",
			       err);
			break;
		}

	} while (false);

	return err;
}
