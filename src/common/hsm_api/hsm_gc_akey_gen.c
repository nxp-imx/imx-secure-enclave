/*
 * Copyright 2023 NXP
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

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_gc_akey_gen.h"

#include "sab_process_msg.h"

#include "plat_utils.h"
#include "plat_os_abs.h"

hsm_err_t hsm_gc_akey_gen(hsm_hdl_t session_hdl, op_gc_akey_gen_args_t *args)
{
	int32_t error;
	struct hsm_session_hdl_s *sess_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	do {
		if (!args)
			break;

		sess_ptr = session_hdl_to_ptr(session_hdl);
		if (!sess_ptr) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		error = process_sab_msg(sess_ptr->phdl,
					sess_ptr->mu_type,
					SAB_GC_AKEY_GEN_REQ,
					MT_SAB_GC_AKEY_GEN,
					(uint32_t)session_hdl,
					args, &rsp_code);

		err = sab_rating_to_hsm_err(error);

		if (err != HSM_NO_ERROR) {
			se_err("HSM Error: SAB_GC_AKEY_GEN_REQ [0x%x].\n", err);
			break;
		}
		err = sab_rating_to_hsm_err(rsp_code);

		if (err != HSM_NO_ERROR)
			se_err("HSM RSP Error: SAB_GC_AKEY_GEN_REQ [0x%x].\n", err);

	} while (false);

	return err;
}
