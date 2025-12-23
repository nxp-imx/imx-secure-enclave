// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023, 2026 NXP
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "internal/hsm_utils.h"
#include "internal/hsm_handle.h"
#include "internal/hsm_lc_update.h"

#include "sab_process_msg.h"
#include "se_lib_serv_intern.h"

#include "plat_utils.h"
#include "plat_os_abs.h"

hsm_err_t hsm_lc_update(hsm_hdl_t session_hdl, op_lc_update_msg_args_t *args)
{
	const uint8_t lc_ret_msg[] = "ROM_DEV_RET_LC_UPDATE";
	const uint8_t lc_fwd_msg[] = "ROM_DEV_FWD_LC_UPDATE";
	struct se_lib_service_hdl_s *se_lib_serv_ptr;
	struct hsm_session_hdl_s *sess_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;
	struct plat_os_abs_hdl *phdl;
	uint32_t rsp_code = 0x0;
	const uint8_t *msg;
	uint32_t mu_type;
	uint32_t error;
	uint8_t msg_id;

	do {
		if (args == NULL)
			break;

		sess_ptr = session_hdl_to_ptr(session_hdl);
		if (sess_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			se_lib_serv_ptr = se_lib_serv_hdl_to_ptr(session_hdl);
			if (!se_lib_serv_ptr || !se_lib_serv_ptr->phdl)
				break;
			phdl = se_lib_serv_ptr->phdl;
			mu_type = se_lib_serv_ptr->mu_type;
		} else {
			phdl = sess_ptr->phdl;
			mu_type = sess_ptr->mu_type;
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

		error = process_sab_msg(phdl,
					mu_type,
					msg_id,
					MT_SAB_LC_UPDATE,
					HSM_HANDLE_NONE,
					args, &rsp_code);

		err = sab_rating_to_hsm_err(error, phdl);

		if (err != HSM_NO_ERROR) {
			se_err("HSM Lib Error: %s [0x%x].\n", msg, err);
			break;
		}
		err = sab_rating_to_hsm_err(rsp_code, phdl);

		if (err != HSM_NO_ERROR)
			se_err("HSM RSP Error: %s [0x%x].\n", msg, err);

	} while (false);

	return err;
}
