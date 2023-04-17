// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "internal/hsm_utils.h"
#include "internal/hsm_handle.h"
#include "internal/hsm_lc_update.h"

#include "sab_process_msg.h"

#include "plat_utils.h"
#include "plat_os_abs.h"

hsm_err_t hsm_lc_update(hsm_hdl_t session_hdl, op_lc_update_msg_args_t *args)
{
	struct hsm_session_hdl_s *sess_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t rsp_code = 0x0;
	int32_t error;
	uint8_t msg_id;
	const uint8_t lc_ret_msg[] = "ROM_DEV_RET_LC_UPDATE";
	const uint8_t lc_fwd_msg[] = "ROM_DEV_FWD_LC_UPDATE";
	const uint8_t *msg;

	do {
		if (args == NULL)
			break;

		sess_ptr = session_hdl_to_ptr(session_hdl);
		if (sess_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		if (((args->new_lc_state | HSM_NXP_FIELD_RET_STATE)
					== HSM_NXP_FIELD_RET_STATE)
			|| ((args->new_lc_state | HSM_OEM_FIELD_RET_STATE)
					== HSM_OEM_FIELD_RET_STATE)) {
			msg_id = ROM_DEV_RET_LC_UPDATE;
			msg = lc_ret_msg;
		} else {
			msg_id = ROM_DEV_FWD_LC_UPDATE;
			msg = lc_fwd_msg;
		}

		error = process_sab_msg(sess_ptr->phdl,
					sess_ptr->mu_type,
					msg_id,
					MT_SAB_LC_UPDATE,
					HSM_HANDLE_NONE,
					args, &rsp_code);

		err = sab_rating_to_hsm_err(error);

		if (err != HSM_NO_ERROR) {
			se_err("HSM Lib Error: %s [0x%x].\n", msg_name, err);
			break;
		}
		err = sab_rating_to_hsm_err(rsp_code);

		if (err != HSM_NO_ERROR)
			se_err("HSM RSP Error: %s [0x%x].\n", msg_name, err);

	} while (false);

	return err;
}
