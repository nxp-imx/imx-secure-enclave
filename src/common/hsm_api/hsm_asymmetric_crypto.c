// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_asymmetric_crypto.h"

#include "sab_process_msg.h"

#ifdef PSA_COMPLIANT
hsm_err_t hsm_asymmetric_enc_open(hsm_hdl_t session_hdl,
				  op_asymmetric_enc_open_args_t *args)
{
	struct hsm_session_hdl_s *sess_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;
	struct hsm_service_hdl_s *asym_serv_ptr;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;
	uint32_t lib_err;

	do {
		if (!args)
			break;

		sess_ptr = session_hdl_to_ptr(session_hdl);
		if (!sess_ptr) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		asym_serv_ptr = add_service(sess_ptr);
		if (!asym_serv_ptr)
			break;

		lib_err = process_sab_msg(sess_ptr->phdl,
					  sess_ptr->mu_type,
					  SAB_ASYMMETRIC_ENC_OPEN_REQ,
					  MT_SAB_ASYMMETRIC_CRYPTO,
					  (uint32_t)session_hdl,
					  args, &rsp_code);

		err = lib_err_to_hsm_err(lib_err);
		if (err != HSM_NO_ERROR)
			break;

		err = sab_rating_to_hsm_err(rsp_code, sess_ptr->phdl);
		if (err != HSM_NO_ERROR) {
			se_err("HSM Error: SAB_ASYMMETRIC_ENC_OPEN_REQ [0x%x].\n", err);
			break;
		}
		asym_serv_ptr->service_hdl = args->asymmetric_enc_handle;
	} while (false);

	return err;
}

hsm_err_t hsm_asymmetric_enc_close(hsm_hdl_t asymmetric_enc_handle)
{
	struct hsm_service_hdl_s *serv_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;
	uint32_t lib_err;

	do {
		if (!asymmetric_enc_handle) {
			se_err("Invalid parameter\n");
			return err;
		}

		serv_ptr = service_hdl_to_ptr(asymmetric_enc_handle);
		if (!serv_ptr) {
			se_err("Service pointer not found\n");
			return err;
		}

		lib_err = process_sab_msg(serv_ptr->session->phdl,
					  serv_ptr->session->mu_type,
					  SAB_ASYMMETRIC_ENC_CLOSE_REQ,
					  MT_SAB_ASYMMETRIC_CRYPTO,
					  (uint32_t)asymmetric_enc_handle,
					  NULL, &rsp_code);

		err = lib_err_to_hsm_err(lib_err);
		if (err != HSM_NO_ERROR)
			break;

		err = sab_rating_to_hsm_err(rsp_code, serv_ptr->session->phdl);
		if (err != HSM_NO_ERROR) {
			se_err("HSM Error: SAB_ASYMMETRIC_ENC_CLOSE_REQ [0x%x].\n", err);
			break;
		}
	} while (false);

	return err;
}

hsm_err_t hsm_asymmetric_enc(hsm_hdl_t session_hdl,
			     op_asymmetric_enc_args_t *args)
{
	struct hsm_session_hdl_s *sess_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;
	uint32_t lib_err;

	do {
		if (!args)
			break;

		sess_ptr = session_hdl_to_ptr(session_hdl);
		if (!sess_ptr) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		lib_err = process_sab_msg(sess_ptr->phdl,
					  sess_ptr->mu_type,
					  SAB_ASYMMETRIC_ENC_REQ,
					  MT_SAB_ASYMMETRIC_CRYPTO,
					  (uint32_t)session_hdl,
					  args, &rsp_code);

		err = lib_err_to_hsm_err(lib_err);
		if (err != HSM_NO_ERROR)
			break;

		err = sab_rating_to_hsm_err(rsp_code, sess_ptr->phdl);
		if (err != HSM_NO_ERROR) {
			se_err("HSM Error: SAB_ASYMMETRIC_ENC_REQ [0x%x].\n", err);
			break;
		}
	} while (false);

	return err;
}
#endif
