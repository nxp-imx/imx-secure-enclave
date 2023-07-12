// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "she_api.h"
#include "sab_process_msg.h"

she_err_t she_open_key_store_service(she_hdl_t session_hdl,
				     open_svc_key_store_args_t *args)
{
	struct she_hdl_s *hdl;
	she_err_t err = SHE_GENERAL_ERROR;
	uint32_t sab_err;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	if (!args) {
		se_err("args cannot be NULL\n");
		return err;
	}

	if (!session_hdl)
		return err;

	hdl = she_session_hdl_to_ptr(session_hdl);
	if (!hdl)
		return err;

#ifndef PSA_COMPLIANT
	if (args->min_mac_length == MIN_MAC_LEN_SET)
		args->flags |= KEY_STORE_OPEN_FLAGS_SET_MAC_LEN;
#endif

	/* Send the signed message to platform if provided here. */
	if (args->signed_message) {
		sab_err = plat_os_abs_send_signed_message(hdl->phdl,
							  args->signed_message,
							  args->signed_msg_size);
		if (sab_err == PLAT_FAILURE)
			return sab_err;
	}

	/* Get the access to the SHE keystore */
	sab_err = process_sab_msg(hdl->phdl,
				  hdl->mu_type,
				  SAB_KEY_STORE_OPEN_REQ,
				  MT_SAB_KEY_STORE,
				  hdl->session_handle,
				  args, &rsp_code);

	err = sab_rating_to_she_err(sab_err);

	if (err != SHE_NO_ERROR) {
		se_err("SHE Error: SAB_KEY_STORE_OPEN_REQ [0x%x].\n", err);
		return err;
	}

	err = sab_rating_to_she_err(rsp_code);

	if (err != SHE_NO_ERROR) {
		se_err("SHE RSP Error: SAB_KEY_STORE_OPEN_REQ [0x%x].\n", err);
		return err;
	}

	return err;
}

she_err_t she_close_key_store_service(she_hdl_t session_hdl)
{
	struct she_hdl_s *hdl;
	she_err_t err = SHE_GENERAL_ERROR;
	uint32_t sab_err;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	hdl = she_session_hdl_to_ptr(session_hdl);
	if (!hdl || !hdl->key_store_handle) {
		se_err("Handle not found\n");
		return err;
	}

	sab_err = process_sab_msg(hdl->phdl,
				  hdl->mu_type,
				  SAB_KEY_STORE_CLOSE_REQ,
				  MT_SAB_KEY_STORE,
				  hdl->key_store_handle,
				  NULL,
				  &rsp_code);

	err = sab_rating_to_she_err(sab_err);

	if (err != SHE_NO_ERROR) {
		se_err("SHE Error: SAB_KEY_STORE_CLOSE_REQ [0x%x].\n", err);
		return err;
	}
	err = sab_rating_to_she_err(rsp_code);
	if (err != SHE_NO_ERROR) {
		se_err("SHE RSP Error: SAB_KEY_STORE_CLOSE_REQ [0x%x].\n", err);
		return err;
	}

	hdl->key_store_handle = 0;

	return err;
}
