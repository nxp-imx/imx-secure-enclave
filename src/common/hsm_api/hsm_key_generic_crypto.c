// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <stdio.h>

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_key_generic_crypto.h"

#include "sab_process_msg.h"

hsm_err_t hsm_open_key_generic_crypto_service(hsm_hdl_t session_hdl,
					      open_svc_key_generic_crypto_args_t *args,
					      hsm_hdl_t *key_generic_crypto_hdl)
{
	struct hsm_session_hdl_s *sess_ptr;
	struct hsm_service_hdl_s *serv_ptr;
	uint32_t error;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;
	hsm_err_t err = HSM_GENERAL_ERROR;

	do {
		if (!args || !key_generic_crypto_hdl)
			break;

		sess_ptr = session_hdl_to_ptr(session_hdl);
		if (!sess_ptr) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		serv_ptr = add_service(sess_ptr);
		if (!serv_ptr)
			break;

		error = process_sab_msg(serv_ptr->session->phdl,
					serv_ptr->session->mu_type,
					SAB_KEY_GENERIC_CRYPTO_SRV_OPEN_REQ,
					MT_SAB_KEY_GENERIC_CRYPTO,
					session_hdl,
					args,
					&rsp_code);

		err = sab_rating_to_hsm_err(error);

		if (err != HSM_NO_ERROR) {
			se_err("HSM Error: SAB_KEY_GENERIC_CRYPTO_OPEN [0x%x].\n", err);
			delete_service(serv_ptr);
			break;
		}

		err = sab_rating_to_hsm_err(rsp_code);

		if (err != HSM_NO_ERROR) {
			se_err("HSM RSP Error:SAB_KEY_GENERIC_CRYPTO_OPEN [0x%x]\n", err);
			delete_service(serv_ptr);
			break;
		}

		serv_ptr->service_hdl = args->key_generic_crypto_hdl;
		*key_generic_crypto_hdl = serv_ptr->service_hdl;
	} while (false);

	return err;
}

hsm_err_t hsm_close_key_generic_crypto_service(hsm_hdl_t key_generic_crypto_hdl)
{
	struct hsm_service_hdl_s *serv_ptr;
	uint32_t error;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;
	hsm_err_t err = HSM_GENERAL_ERROR;

	do {
		if (!key_generic_crypto_hdl)
			break;

		serv_ptr = service_hdl_to_ptr(key_generic_crypto_hdl);
		if (!serv_ptr) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		error = process_sab_msg(serv_ptr->session->phdl,
					serv_ptr->session->mu_type,
					SAB_KEY_GENERIC_CRYPTO_SRV_CLOSE_REQ,
					MT_SAB_KEY_GENERIC_CRYPTO,
					key_generic_crypto_hdl,
					NULL,
					&rsp_code);

		err = sab_rating_to_hsm_err(error);

		if (err != HSM_NO_ERROR) {
			se_err("HSM Error: SAB_KEY_GENERIC_CRYPTO_CLOSE [0x%x]\n", err);
			delete_service(serv_ptr);
			break;
		}

		err = sab_rating_to_hsm_err(rsp_code);

		if (err != HSM_NO_ERROR)
			se_err("HSM RSP Err:SAB_KEY_GENERIC_CRYPTO_CLOSE [0x%x]\n", err);
		/*
		 *  Do not delete the service if SAB_ERR is 0x0429.
		 *  i.e. in case of HSM_INVALID_PARAM (0x04)
		 */
		if (err != HSM_INVALID_PARAM)
			delete_service(serv_ptr);

	} while (false);

	return err;
}

hsm_err_t hsm_key_generic_crypto(hsm_hdl_t key_generic_crypto_hdl,
				 op_key_generic_crypto_args_t *args)
{
	struct hsm_service_hdl_s *serv_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;
	uint32_t error;

	do {
		if (!args)
			break;

		if (!key_generic_crypto_hdl) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		serv_ptr = service_hdl_to_ptr(key_generic_crypto_hdl);
		if (!serv_ptr) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		error = process_sab_msg(serv_ptr->session->phdl,
					serv_ptr->session->mu_type,
					SAB_KEY_GENERIC_CRYPTO_SRV_REQ,
					MT_SAB_KEY_GENERIC_CRYPTO,
					key_generic_crypto_hdl,
					args,
					&rsp_code);

		err = sab_rating_to_hsm_err(error);

		if (err != HSM_NO_ERROR) {
			se_err("HSM Error: SAB_KEY_GENERIC_CRYPTO_SRV [0x%x].\n", err);
			break;
		}

		err = sab_rating_to_hsm_err(rsp_code);

		if (err != HSM_NO_ERROR) {
			se_err("HSM RSP Error:SAB_KEY_GENERIC_CRYPTO_SRV [0x%x].\n", err);
			break;
		}

	} while (false);

	return err;
}
