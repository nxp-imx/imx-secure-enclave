// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
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
	uint32_t error;

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

		/* Send the signed message to platform if provided here. */
		if (args->signed_message) {
			error = plat_os_abs_send_signed_message(serv_ptr->session->phdl,
								args->signed_message,
								args->signed_msg_size);
			if (error == PLAT_FAILURE)
				break;
		}

		error = process_sab_msg(serv_ptr->session->phdl,
					serv_ptr->session->mu_type,
					SAB_KEY_STORE_OPEN_REQ,
					MT_SAB_KEY_STORE,
					session_hdl,
					args, &rsp_code);

		err = sab_rating_to_hsm_err(error);

		if (err != HSM_NO_ERROR) {
			se_err("HSM Error: SAB_KEY_STORE_OPEN_REQ [0x%x].\n",
			       err);
			delete_service(serv_ptr);
			break;
		}

		err = sab_rating_to_hsm_err(rsp_code);

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
	uint32_t error;
	hsm_err_t err = HSM_UNKNOWN_HANDLE;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	do {
		if (!key_store_hdl)
			break;

		serv_ptr = service_hdl_to_ptr(key_store_hdl);

		if (!serv_ptr)
			break;

		error = process_sab_msg(serv_ptr->session->phdl,
					serv_ptr->session->mu_type,
					SAB_KEY_STORE_CLOSE_REQ,
					MT_SAB_KEY_STORE,
					(uint32_t)key_store_hdl,
					NULL,
					&rsp_code);

		err = sab_rating_to_hsm_err(error);

		if (err != HSM_NO_ERROR) {
			se_err("HSM Error: SAB_KEY_STORE_CLOSE_REQ [0x%x].\n",
			       err);
			break;
		}

		err = sab_rating_to_hsm_err(rsp_code);

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
