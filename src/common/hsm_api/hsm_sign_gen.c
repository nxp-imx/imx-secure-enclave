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
#include "internal/hsm_sign_gen.h"

#include "sab_process_msg.h"

hsm_err_t hsm_open_signature_generation_service(hsm_hdl_t key_store_hdl,
						open_svc_sign_gen_args_t *args,
						hsm_hdl_t *signature_gen_hdl)
{
	struct hsm_service_hdl_s *key_store_serv_ptr;
	struct hsm_service_hdl_s *sig_gen_serv_ptr;
	int32_t error = 1;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t rsp_code;

	do {
		if ((args == NULL) || (signature_gen_hdl == NULL)) {
			break;
		}
		key_store_serv_ptr = service_hdl_to_ptr(key_store_hdl);
		if (key_store_serv_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		sig_gen_serv_ptr = add_service(key_store_serv_ptr->session);
		if (sig_gen_serv_ptr == NULL) {
			break;
		}

		error = process_sab_msg(key_store_serv_ptr->session->phdl,
					key_store_serv_ptr->session->mu_type,
					SAB_SIGNATURE_GENERATION_OPEN_REQ,
					MT_SAB_SIGN_GEN,
					(uint32_t)key_store_hdl,
					args, &rsp_code);
		err = sab_rating_to_hsm_err(error);

		if (err != HSM_NO_ERROR) {
			printf("HSM Error: SAB_SIGNATURE_GENERATION_OPEN_REQ [0x%x].\n", err);
			delete_service(sig_gen_serv_ptr);
			break;
		}

		err = sab_rating_to_hsm_err(rsp_code);

		if (err != HSM_NO_ERROR) {
			printf("HSM RSP Error: SAB_SIGNATURE_GENERATION_OPEN_REQ [0x%x].\n", err);
			delete_service(sig_gen_serv_ptr);
			break;
		}

		sig_gen_serv_ptr->service_hdl = args->signature_gen_hdl;
		*signature_gen_hdl = args->signature_gen_hdl;
	} while (false);

	return err;
}

hsm_err_t hsm_close_signature_generation_service(hsm_hdl_t signature_gen_hdl)
{
	struct hsm_service_hdl_s *serv_ptr;
	int32_t error = 1;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t rsp_code;

	do {
		serv_ptr = service_hdl_to_ptr(signature_gen_hdl);
		if (serv_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		error = process_sab_msg(serv_ptr->session->phdl,
					serv_ptr->session->mu_type,
					SAB_SIGNATURE_GENERATION_CLOSE_REQ,
					MT_SAB_SIGN_GEN,
					(uint32_t)signature_gen_hdl,
					NULL, &rsp_code);

		err = sab_rating_to_hsm_err(error);
		if (err != HSM_NO_ERROR) {
			printf("HSM Error: SAB_SIGNATURE_GENERATION_CLOSE_REQ [0x%x].\n", err);
			delete_service(serv_ptr);
			break;
		}

		err = sab_rating_to_hsm_err(rsp_code);
		if (err != HSM_NO_ERROR) {
			printf("HSM RSP Error: SAB_SIGNATURE_GENERATION_CLOSE_REQ [0x%x].\n", err);
		}
		delete_service(serv_ptr);
	} while (false);

	return err;
}

hsm_err_t hsm_generate_signature(hsm_hdl_t signature_gen_hdl,
					op_generate_sign_args_t *args)
{
	int32_t error = 1;
	struct hsm_service_hdl_s *serv_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t rsp_code;

	do {
		if (args == NULL) {
			break;
		}
		serv_ptr = service_hdl_to_ptr(signature_gen_hdl);
		if (serv_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		error = process_sab_msg(serv_ptr->session->phdl,
					serv_ptr->session->mu_type,
					SAB_SIGNATURE_GENERATE_REQ,
					MT_SAB_SIGN_GEN,
					(uint32_t)signature_gen_hdl,
					args, &rsp_code);

		err = sab_rating_to_hsm_err(error);
		if (err != HSM_NO_ERROR) {
			printf("HSM Error: SAB_SIGNATURE_GENERATE_REQ [0x%x].\n", err);
			break;
		}

		err = sab_rating_to_hsm_err(rsp_code);
		if (err != HSM_NO_ERROR) {
			printf("HSM RSP Error: SAB_SIGNATURE_GENERATE_REQ [0x%x].\n", err);
		}
	} while (false);

	return err;
}

hsm_err_t hsm_prepare_signature(hsm_hdl_t signature_gen_hdl,
				op_prepare_sign_args_t *args)
{
	int32_t error = 1;
	struct hsm_service_hdl_s *serv_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t rsp_code;

	do {
		if (args == NULL) {
			break;
		}
		serv_ptr = service_hdl_to_ptr(signature_gen_hdl);
		if (serv_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}
		error = process_sab_msg(serv_ptr->session->phdl,
					serv_ptr->session->mu_type,
					SAB_SIGNATURE_PREPARE_REQ,
					MT_SAB_SIGN_GEN,
					(uint32_t)signature_gen_hdl,
					args, &rsp_code);

		err = sab_rating_to_hsm_err(error);
		if (err != HSM_NO_ERROR) {
			printf("HSM Error: SAB_SIGNATURE_PREPARE_REQ [0x%x].\n", err);
			break;
		}

		err = sab_rating_to_hsm_err(rsp_code);
		if (err != HSM_NO_ERROR) {
			printf("HSM RSP Error: SAB_SIGNATURE_PREPARE_REQ [0x%x].\n", err);
		}

	} while (false);

	return err;
}

hsm_err_t hsm_do_sign(hsm_hdl_t key_store_hdl,
			op_generate_sign_args_t *args)
{
	hsm_err_t hsmret = HSM_GENERAL_ERROR;
	hsm_hdl_t sig_gen_hdl;
	open_svc_sign_gen_args_t open_sig_gen_args = {
						.flags = args->svc_flags,
						};

	hsmret = hsm_open_signature_generation_service(key_store_hdl,
					&open_sig_gen_args, &sig_gen_hdl);
	if (hsmret) {
		printf("hsm_open_signature_generation_service ret:0x%x\n",
				hsmret);
		goto exit;
	}

	hsmret = hsm_generate_signature(sig_gen_hdl, args);
	if (hsmret)
		printf("hsm_generate_signature ret:0x%x\n", hsmret);

	hsmret = hsm_close_signature_generation_service(sig_gen_hdl);
	if (hsmret)
		printf("hsm_close_signature_generation_service ret:0x%x\n",
				hsmret);

exit:
	return hsmret;
}
