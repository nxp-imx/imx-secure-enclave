// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include "internal/hsm_utils.h"
#include "internal/hsm_handle.h"
#include "internal/hsm_debug_dump.h"

#include "sab_msg_def.h"
#include "sab_process_msg.h"

hsm_err_t dump_firmware_log(hsm_hdl_t session_hdl)
{
/* Firmware dump is not supported by SECO.
 */
#ifndef CONFIG_PLAT_ELE
	return HSM_GENERAL_ERROR;
#endif
	struct hsm_session_hdl_s *sess_ptr;
	uint32_t error;
	hsm_err_t err = HSM_UNKNOWN_HANDLE;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;
	op_debug_dump_args_t args = {0};
	int i = 0;

	do {
		if (!session_hdl)
			break;

		sess_ptr = session_hdl_to_ptr(session_hdl);

		if (!sess_ptr)
			break;

		error = process_sab_msg(sess_ptr->phdl,
					sess_ptr->mu_type,
					ROM_DEBUG_DUMP_REQ,
					MT_SAB_DEBUG_DUMP,
					HSM_HANDLE_NONE,
					&args, &rsp_code);

		err = sab_rating_to_hsm_err(error, sess_ptr->phdl);
		if (err == HSM_NO_ERROR) {
			for (i = 0; i < args.dump_buf_len; i++) {
				if ((i % 2) == 0)
					se_print("\nS40X: ");
				se_print("0x%08x ", args.dump_buf[i]);
			}
			se_print("\n\n");
		} else {
			se_err("Dump_Debug_Buffer Error: %x ", error);
			break;
		}

	} while (args.is_dump_pending == true);
	se_print("\n");

	return err;
}
