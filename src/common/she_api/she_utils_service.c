// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "she_api.h"
#include "sab_process_msg.h"

she_err_t she_open_utils(she_hdl_t session_hdl, op_open_utils_args_t *args)
{
	struct she_hdl_s *hdl;
	she_err_t err = SHE_GENERAL_ERROR;
	uint32_t sab_err;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	if (!args || !session_hdl) {
		se_err("args/session handle cannot be NULL\n");
		return err;
	}

	hdl = she_session_hdl_to_ptr(session_hdl);
	if (!hdl || !hdl->key_store_handle) {
		se_err("Handle not found\n");
		return err;
	}

	if (hdl->utils_handle != 0u) {
		se_err("SHE: Utils handle already open\n");
		return err;
	}

	/* Get the access to SHE utils */
	sab_err = process_sab_msg(hdl->phdl,
				  hdl->mu_type,
				  SAB_SHE_UTILS_OPEN,
				  MT_SAB_UTILS,
				  hdl->key_store_handle,
				  args,
				  &rsp_code);

	err = sab_rating_to_she_err(sab_err);

	if (err != SHE_NO_ERROR) {
		se_err("SHE Error: SAB_SHE_UTILS_OPEN [0x%x].\n", err);
		return err;
	}

	err = sab_rating_to_she_err(rsp_code);

	if (err != SHE_NO_ERROR) {
		se_err("SHE RSP Error: SAB_SHE_UTILS_OPEN [0x%x].\n", err);
		return err;
	}

	return err;
}

she_err_t she_close_utils(she_hdl_t session_hdl)
{
	struct she_hdl_s *hdl;
	she_err_t err = SHE_GENERAL_ERROR;
	uint32_t sab_err;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	hdl = she_session_hdl_to_ptr(session_hdl);
	if (!hdl || !hdl->utils_handle) {
		se_err("Handle not found\n");
		return err;
	}

	sab_err = process_sab_msg(hdl->phdl,
				  hdl->mu_type,
				  SAB_SHE_UTILS_CLOSE,
				  MT_SAB_UTILS,
				  hdl->utils_handle,
				  NULL,
				  &rsp_code);

	err = sab_rating_to_she_err(sab_err);

	if (err != SHE_NO_ERROR) {
		se_err("SHE Error: SAB_SHE_UTILS_CLOSE [0x%x].\n", err);
		return err;
	}
	err = sab_rating_to_she_err(rsp_code);
	if (err != SHE_NO_ERROR) {
		se_err("SHE RSP Error: SAB_SHE_UTILS_CLOSE [0x%x].\n", err);
		return err;
	}

	return err;
}
