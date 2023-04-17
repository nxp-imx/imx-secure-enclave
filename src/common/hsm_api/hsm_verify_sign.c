// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
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
	uint32_t error;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	do {
		if ((args == NULL) || (signature_ver_hdl == NULL)) {
			break;
		}

		if (!session_hdl) {
			err = HSM_UNKNOWN_HANDLE;
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

		err = sab_rating_to_hsm_err(error);
		if (err != HSM_NO_ERROR) {
			se_err("HSM Error: SAB_SIGNATURE_VERIFICATION_OPEN_REQ [0x%x].\n", err);
			delete_service(serv_ptr);
			break;
		}

		err = sab_rating_to_hsm_err(rsp_code);
		if (err != HSM_NO_ERROR) {
			se_err("HSM RSP Error: SAB_SIGNATURE_VERIFICATION_OPEN_REQ [0x%x].\n", err);
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
	uint32_t error;
	hsm_err_t err = HSM_UNKNOWN_HANDLE;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	do {
		if (!signature_ver_hdl)
			break;

		serv_ptr = service_hdl_to_ptr(signature_ver_hdl);
		if (!serv_ptr)
			break;

		error = process_sab_msg(serv_ptr->session->phdl,
					serv_ptr->session->mu_type,
					SAB_SIGNATURE_VERIFICATION_CLOSE_REQ,
					MT_SAB_VERIFY_SIGN,
					(uint32_t)signature_ver_hdl,
					NULL, &rsp_code);

		err = sab_rating_to_hsm_err(error);
		if (err != HSM_NO_ERROR) {
			se_err("HSM Error: SAB_SIGNATURE_VERIFICATION_CLOSE_REQ [0x%x].\n", err);
			delete_service(serv_ptr);
			break;
		}

		err = sab_rating_to_hsm_err(rsp_code);
		if (err != HSM_NO_ERROR) {
			se_err("HSM RSP Error: SAB_SIGNATURE_VERIFICATION_CLOSE_REQ [0x%x].\n", err);
		}
		delete_service(serv_ptr);
	} while (false);

	return err;
}

hsm_err_t hsm_verify_signature(hsm_hdl_t signature_ver_hdl,
				op_verify_sign_args_t *args,
				hsm_verification_status_t *status)
{
	uint32_t error;
	struct hsm_service_hdl_s *serv_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	do {
		if ((args == NULL) || (status == NULL)) {
			break;
		}
		args->verification_status = HSM_VERIFICATION_STATUS_FAILURE;

		if (!signature_ver_hdl) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		serv_ptr = service_hdl_to_ptr(signature_ver_hdl);
		if (serv_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		error = process_sab_msg(serv_ptr->session->phdl,
					serv_ptr->session->mu_type,
					SAB_SIGNATURE_VERIFY_REQ,
					MT_SAB_VERIFY_SIGN,
					(uint32_t)signature_ver_hdl,
					args, &rsp_code);

		err = sab_rating_to_hsm_err(error);
		if (err != HSM_NO_ERROR) {
			se_err("HSM Error: SAB_SIGNATURE_VERIFY_REQ [0x%x].\n",
				err);
			break;
		}

		*status = args->verification_status;

		err = sab_rating_to_hsm_err(rsp_code);

		if (err != HSM_NO_ERROR) {
			se_err("HSM RSP Error: SAB_SIGNATURE_VERIFY_REQ [0x%x].\n",
				err);
			break;
		}

		/* Since, by default the verification status is invalid at FW,
		 * verification status would be not equal to
		 * HSM_VERIFICATION_STATUS_SUCCESS
		 */
		if (args->verification_status != HSM_VERIFICATION_STATUS_SUCCESS) {
			err = HSM_SIGNATURE_INVALID;
			se_err("\nHSM RSP Error: HSM_SIGNATURE_INVALID (0x%x)\n",
			       HSM_SIGNATURE_INVALID);
		}

	} while (false);

	return err;
}

hsm_err_t hsm_verify_sign(hsm_hdl_t session_hdl,
			  op_verify_sign_args_t *args,
			  hsm_verification_status_t *status)
{
	hsm_err_t hsmret;
	/* Stores the error status of the main operation.
	 */
	hsm_err_t op_err;
	hsm_hdl_t sig_ver_hdl = 0;
	open_svc_sign_ver_args_t open_sig_ver_args = {0};
#ifndef PSA_COMPLIANT
	open_sig_ver_args.flags = args->svc_flags;
#endif
	op_err = hsm_open_signature_verification_service(session_hdl,
							 &open_sig_ver_args,
							 &sig_ver_hdl);
	if (op_err) {
		se_err("hsm_open_signature_verification_service ret:0x%x\n",
				op_err);
		goto exit;
	}

	op_err = hsm_verify_signature(sig_ver_hdl, args, status);
	if (op_err)
		se_err("hsm_verify_signature ret:0x%x\n", op_err);

	hsmret = hsm_close_signature_verification_service(sig_ver_hdl);
	if (hsmret) {
		se_err("hsm_close_signature_verification_service ret:0x%x\n",
				hsmret);
		if (op_err == HSM_NO_ERROR)
			op_err = hsmret;
	}

exit:
	return op_err;
}
