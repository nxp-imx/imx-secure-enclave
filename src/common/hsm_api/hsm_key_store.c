// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#include <stdio.h>

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_key_store.h"

#include "plat_utils.h"
#include "sab_process_msg.h"

hsm_err_t hsm_open_key_store_service(hsm_hdl_t session_hdl,
				     open_svc_key_store_args_t *args,
				     hsm_hdl_t *key_store_hdl)
{
	struct hsm_session_hdl_s *sess_ptr;
	struct hsm_service_hdl_s *serv_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;
	uint32_t lib_err;

	do {
		if (!args || !key_store_hdl)
			break;

		if (!session_hdl) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		sess_ptr = session_hdl_to_ptr(session_hdl);
		if (!sess_ptr) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		serv_ptr = add_service(sess_ptr);
		if (!serv_ptr)
			break;
#ifndef PSA_COMPLIANT
		/* Send the signed message to platform if provided here. */
		if (args->signed_message) {
			lib_err = plat_os_abs_send_signed_message_v2
					(serv_ptr->session->phdl,
					 args->signed_message,
					 args->signed_msg_size);

			err = plat_err_to_hsm_err(SAB_KEY_STORE_OPEN_REQ,
						  lib_err,
						  HSM_PREPARE);

			if (err != HSM_NO_ERROR)
				break;
		}
#endif
		lib_err = process_sab_msg(serv_ptr->session->phdl,
					  serv_ptr->session->mu_type,
					  SAB_KEY_STORE_OPEN_REQ,
					  MT_SAB_KEY_STORE,
					  session_hdl,
					  args, &rsp_code);

		err = lib_err_to_hsm_err(lib_err);
		if (err != HSM_NO_ERROR) {
			delete_service(serv_ptr);
			break;
		}

		err = sab_rating_to_hsm_err(rsp_code, serv_ptr->session->phdl);

		if (err != HSM_NO_ERROR) {
			se_err("HSM RSP Error: SAB_KEY_STORE_OPEN_REQ [0x%x].\n",
			       err);
			delete_service(serv_ptr);
			break;
		}

		serv_ptr->service_hdl = args->key_store_hdl;
		*key_store_hdl = serv_ptr->service_hdl;
	} while (false);

	return err;
}

hsm_err_t hsm_close_key_store_service(hsm_hdl_t key_store_hdl)
{
	struct hsm_service_hdl_s *serv_ptr;
	hsm_err_t err = HSM_UNKNOWN_HANDLE;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;
	uint32_t lib_err;

	do {
		if (!key_store_hdl)
			break;

		serv_ptr = service_hdl_to_ptr(key_store_hdl);

		if (!serv_ptr)
			break;

		lib_err = process_sab_msg(serv_ptr->session->phdl,
					  serv_ptr->session->mu_type,
					  SAB_KEY_STORE_CLOSE_REQ,
					  MT_SAB_KEY_STORE,
					  (uint32_t)key_store_hdl,
					  NULL,
					  &rsp_code);

		err = lib_err_to_hsm_err(lib_err);
		if (err != HSM_NO_ERROR)
			break;

		err = sab_rating_to_hsm_err(rsp_code, serv_ptr->session->phdl);

		if (err != HSM_NO_ERROR)
			se_err("HSM RSP Error: SAB_KEY_STORE_CLOSE_REQ [0x%x].\n",
			       err);

		/*
		 * Do not delete the service if SAB_ERR is 0x0429.
		 * i.e. in case of HSM_INVALID_PARAM (0x04)
		 */
		if (err != HSM_INVALID_PARAM)
			delete_service(serv_ptr);

	} while (false);

	return err;
}

hsm_err_t hsm_key_store_reprov_en(hsm_hdl_t session_hdl,
				  op_key_store_reprov_en_args_t *args)
{
	hsm_err_t err = HSM_GENERAL_ERROR;
	struct hsm_session_hdl_s *sess_ptr;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;
	uint32_t lib_err;

	do {
		if (!args)
			break;

		if (!session_hdl) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		sess_ptr = session_hdl_to_ptr(session_hdl);
		if (!sess_ptr) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		lib_err = process_sab_msg(sess_ptr->phdl,
					  sess_ptr->mu_type,
					  SAB_KEY_STORE_REPROV_EN_REQ,
					  MT_SAB_KEY_STORE_REPROV_EN,
					  (uint32_t)session_hdl,
					  args,
					  &rsp_code);

		err = lib_err_to_hsm_err(lib_err);
		if (err != HSM_NO_ERROR)
			break;

		err = sab_rating_to_hsm_err(rsp_code, sess_ptr->phdl);

		if (err != HSM_NO_ERROR) {
			se_err("HSM RSP Error: SAB_KEY_STORE_REPROV_EN_REQ [0x%x].\n",
			       err);
			break;
		}
	} while (false);

	return err;
}
