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

		if (error == 0) {
			for (i = 0; i < args.dump_buf_len; i++) {
				if ((i % 10) == 0)
					printf("\n");
				printf("%08x ", args.dump_buf[i]);
			}
		} else
			break;

	} while (args.dump_buf_len == 20);
	printf("\n");

	return err;
}
