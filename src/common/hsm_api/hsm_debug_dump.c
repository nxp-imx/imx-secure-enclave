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
	int32_t error = 1;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t rsp_code = 0x0;
	op_debug_dump_args_t args;
	int i = 0;

	do {
		sess_ptr = session_hdl_to_ptr(session_hdl);
		if (sess_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		error = process_sab_msg(sess_ptr->phdl,
					sess_ptr->mu_type,
					ROM_DEBUG_DUMP_REQ,
					MT_SAB_DEBUG_DUMP,
					HSM_HANDLE_NONE,
					&args, &rsp_code);

		err = sab_rating_to_hsm_err(error);
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
