// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "she_api.h"
#include "sab_process_msg.h"

she_err_t she_open_cipher_service(she_hdl_t session_hdl,
				  open_svc_cipher_args_t *args)
{
	struct she_hdl_s *hdl;
	she_err_t err = SHE_GENERAL_ERROR;
	uint32_t sab_err;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	if (!args) {
		se_err("args cannot be NULL\n");
		return err;
	}

	hdl = she_session_hdl_to_ptr(session_hdl);
	if (!hdl || !hdl->key_store_handle) {
		se_err("Handle not found\n");
		return err;
	}

	sab_err = process_sab_msg(hdl->phdl,
				  hdl->mu_type,
				  SAB_CIPHER_OPEN_REQ,
				  MT_SAB_CIPHER,
				  hdl->key_store_handle,
				  args,
				  &rsp_code);

	err = sab_rating_to_she_err(sab_err);

	if (err != SHE_NO_ERROR) {
		se_err("SHE Error: SAB_CIPHER_OPEN_REQ [0x%x].\n", err);
		return err;
	}

	err = sab_rating_to_she_err(rsp_code);

	if (err != SHE_NO_ERROR) {
		se_err("SHE RSP Error: SAB_SHE_UTILS_OPEN [0x%x].\n", err);
		return err;
	}

	return err;
}

she_err_t she_close_cipher_service(she_hdl_t session_hdl)
{
	struct she_hdl_s *hdl;
	she_err_t err = SHE_GENERAL_ERROR;
	uint32_t sab_err;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	hdl = she_session_hdl_to_ptr(session_hdl);
	if (!hdl || !hdl->cipher_handle) {
		se_err("Handle not found\n");
		return err;
	}

	sab_err = process_sab_msg(hdl->phdl,
				  hdl->mu_type,
				  SAB_CIPHER_CLOSE_REQ,
				  MT_SAB_CIPHER,
				  hdl->cipher_handle,
				  NULL,
				  &rsp_code);

	err = sab_rating_to_she_err(sab_err);

	if (err != SHE_NO_ERROR) {
		se_err("SHE Error: SAB_CIPHER_CLOSE_REQ [0x%x].\n", err);
		return err;
	}
	err = sab_rating_to_she_err(rsp_code);
	if (err != SHE_NO_ERROR) {
		se_err("SHE RSP Error: SAB_CIPHER_CLOSE_REQ [0x%x].\n", err);
		return err;
	}

	return err;
}
