// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "she_api.h"
#include "sab_process_msg.h"

she_err_t she_get_info(she_hdl_t session_hdl, op_get_info_args_t *args)
{
	struct she_hdl_s *hdl;
	she_err_t err = SHE_GENERAL_ERROR;
	uint32_t sab_err;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	if (!args || !session_hdl) {
		se_err("incorrect input parameters\n");
		return err;
	}

	hdl = she_session_hdl_to_ptr(session_hdl);
	if (!hdl) {
		se_err("Handle not found\n");
		return err;
	}

	sab_err = process_sab_msg(hdl->phdl,
				  hdl->mu_type,
				  SAB_GET_INFO_REQ,
				  MT_SAB_GET_INFO,
				  hdl->session_handle,
				  args,
				  &rsp_code);

	err = sab_rating_to_she_err(sab_err);

	if (err != SHE_NO_ERROR) {
		se_err("SHE Error: SAB_GET_INFO_REQ [0x%x].\n", err);
		return err;
	}

	err = sab_rating_to_she_err(rsp_code);

	if (err != SHE_NO_ERROR) {
		se_err("SHE RSP Error: SAB_GET_INFO_REQ [0x%x].\n", err);
		return err;
	}

	return err;
}
