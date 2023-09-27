// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "she_api.h"
#include "sab_process_msg.h"

she_err_t she_open_key_store_service(she_hdl_t session_hdl,
				     open_svc_key_store_args_t *args)
{
	struct she_session_hdl_s *sess_ptr;
	struct she_service_hdl_s *serv_ptr;
	she_err_t err = SHE_GENERAL_ERROR;
	uint32_t lib_err;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	if (!args) {
		se_err("args cannot be NULL\n");
		return err;
	}

	if (!session_hdl)
		return err;

	sess_ptr = she_session_hdl_to_ptr(session_hdl);
	if (!sess_ptr)
		return err;

	serv_ptr = add_she_service(sess_ptr);
	if (!serv_ptr)
		return err;

#ifndef PSA_COMPLIANT
	if (!(args->flags & KEY_STORE_OPEN_FLAGS_SET_MAC_LEN))
		args->min_mac_length = 0;
#endif

	/* Send the signed message to platform if provided here. */
	if (args->signed_message) {
		lib_err = plat_os_abs_send_signed_message_v2(sess_ptr->phdl,
							     args->signed_message,
							     args->signed_msg_size);
		err = plat_err_to_she_err(SAB_KEY_STORE_OPEN_REQ,
					  lib_err,
					  SHE_PREPARE);

		if (err != SHE_NO_ERROR)
			return err;
	}

	/* Get the access to the SHE keystore */
	lib_err = process_sab_msg(sess_ptr->phdl,
				  sess_ptr->mu_type,
				  SAB_KEY_STORE_OPEN_REQ,
				  MT_SAB_KEY_STORE,
				  sess_ptr->session_hdl,
				  args, &rsp_code);

	sess_ptr->last_rating = rsp_code;
#ifdef V2
	err = lib_err_to_she_err(lib_err);
	if (err != SHE_NO_ERROR) {
		delete_she_service(serv_ptr);
		return err;
	}
#endif
	err = sab_rating_to_she_err(rsp_code);

	if (err != SHE_NO_ERROR) {
		se_err("SHE RSP Error: SAB_KEY_STORE_OPEN_REQ [0x%x].\n", err);
		delete_she_service(serv_ptr);
		return err;
	}

	serv_ptr->service_hdl = args->key_store_hdl;

	return err;
}

she_err_t she_close_key_store_service(she_hdl_t key_store_handle)
{
	struct she_service_hdl_s *serv_ptr;
	she_err_t err = SHE_GENERAL_ERROR;
	uint32_t lib_err;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	if (!key_store_handle) {
		se_err("Invalid parameter\n");
		return err;
	}

	serv_ptr = she_service_hdl_to_ptr(key_store_handle);
	if (!serv_ptr) {
		se_err("Service pointer not found\n");
		return err;
	}

	lib_err = process_sab_msg(serv_ptr->session->phdl,
				  serv_ptr->session->mu_type,
				  SAB_KEY_STORE_CLOSE_REQ,
				  MT_SAB_KEY_STORE,
				  (uint32_t)key_store_handle,
				  NULL,
				  &rsp_code);

	serv_ptr->session->last_rating = rsp_code;

	err = lib_err_to_she_err(lib_err);
	if (err != SHE_NO_ERROR)
		return err;

	err = sab_rating_to_she_err(rsp_code);
	if (err != SHE_NO_ERROR) {
		se_err("SHE RSP Error: SAB_KEY_STORE_CLOSE_REQ [0x%x].\n", err);
		return err;
	}

	delete_she_service(serv_ptr);

	return err;
}
