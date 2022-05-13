/*
 * Copyright 2022 NXP
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

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_verify_sign.h"

#include "sab_process_msg.h"

hsm_err_t hsm_open_signature_verification_service(hsm_hdl_t session_hdl,
						open_svc_sign_ver_args_t *args,
						hsm_hdl_t *signature_ver_hdl)
{
	struct hsm_session_hdl_s *sess_ptr;
	struct hsm_service_hdl_s *serv_ptr;
	int32_t error = 1;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t rsp_code;

	do {
		if ((args == NULL) || (signature_ver_hdl == NULL)) {
			break;
		}
		sess_ptr = session_hdl_to_ptr(session_hdl);
		if (sess_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		serv_ptr = add_service(sess_ptr);
		if (serv_ptr == NULL) {
			break;
		}

		error = process_sab_msg(serv_ptr->session->phdl,
					serv_ptr->session->mu_type,
					SAB_SIGNATURE_VERIFICATION_OPEN_REQ,
					MT_SAB_VERIFY_SIGN,
					(uint32_t)session_hdl,
					args, &rsp_code);


		if (error != 0) {
			delete_service(serv_ptr);
			break;
		}

		err = sab_rating_to_hsm_err(rsp_code);
		if (err != HSM_NO_ERROR) {
			delete_service(serv_ptr);
			break;
		}
		serv_ptr->service_hdl = args->sig_ver_hdl;
		*signature_ver_hdl = args->sig_ver_hdl;
	} while (false);

	return err;
}

hsm_err_t hsm_close_signature_verification_service(hsm_hdl_t signature_ver_hdl)
{
	struct hsm_service_hdl_s *serv_ptr;
	int32_t error = 1;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t rsp_code;

	do {
		serv_ptr = service_hdl_to_ptr(signature_ver_hdl);
		if (serv_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		error = process_sab_msg(serv_ptr->session->phdl,
					serv_ptr->session->mu_type,
					SAB_SIGNATURE_VERIFICATION_CLOSE_REQ,
					MT_SAB_VERIFY_SIGN,
					(uint32_t)signature_ver_hdl,
					NULL, &rsp_code);

		if (error == 0) {
			err = sab_rating_to_hsm_err(rsp_code);
		}
		delete_service(serv_ptr);
	} while (false);

	return err;
}

hsm_err_t hsm_verify_signature(hsm_hdl_t signature_ver_hdl,
				op_verify_sign_args_t *args,
				hsm_verification_status_t *status)
{
	int32_t error = 1;
	struct hsm_service_hdl_s *serv_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t rsp_code;

	do {
		if ((args == NULL) || (status == NULL)) {
			break;
		}
		serv_ptr = service_hdl_to_ptr(signature_ver_hdl);
		if (serv_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

#ifdef PSA_COMPLIANT
		error = set_key_type_n_sz(args->key_type,
					&args->key_sz,
					&args->psa_key_type,
					NULL);

		if (error) {
			printf("HSM Error: Invalid Key Type is given [0x%x].\n",
				args->key_type);
			break;
		}
#endif

		error = process_sab_msg(serv_ptr->session->phdl,
					serv_ptr->session->mu_type,
					SAB_SIGNATURE_VERIFY_REQ,
					MT_SAB_VERIFY_SIGN,
					(uint32_t)signature_ver_hdl,
					args, &rsp_code);
		if (error != 0) {
			printf("SAB Send/Receive Err[0x%x]:SAB_VER_SIG_REQ.\n",
								rsp_code);
			break;
		}

		if (rsp_code)
			printf("SAB FW Error[0x%x]: SAB_VER_SIG_REQ.\n",
								rsp_code);

		err = sab_rating_to_hsm_err(rsp_code);
		*status = args->verification_status;
	} while (false);

	return err;
}
