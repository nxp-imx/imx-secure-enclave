/*
 * Copyright 2019-2022 NXP
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
#include <stdio.h>

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_cipher.h"

#include "sab_process_msg.h"

hsm_err_t hsm_open_cipher_service(hsm_hdl_t key_store_hdl,
				  open_svc_cipher_args_t *args,
				  hsm_hdl_t *cipher_hdl)
{
	struct hsm_service_hdl_s *key_store_serv_ptr;
	struct hsm_service_hdl_s *cipher_serv_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t rsp_code;
	int32_t error;

	do {
		if ((args == NULL) || (cipher_hdl == NULL)) {
			break;
		}
		key_store_serv_ptr = service_hdl_to_ptr(key_store_hdl);
		if (key_store_serv_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		cipher_serv_ptr = add_service(key_store_serv_ptr->session);
		if (cipher_serv_ptr == NULL) {
			break;
		}

		error = process_sab_msg(key_store_serv_ptr->session->phdl,
					key_store_serv_ptr->session->mu_type,
					SAB_CIPHER_OPEN_REQ,
					MT_SAB_CIPHER,
					(uint32_t)key_store_hdl,
					args, &rsp_code);
		err = sab_rating_to_hsm_err(rsp_code);

		if (!error && err != HSM_NO_ERROR) {
			delete_service(cipher_serv_ptr);
			break;
		}
		cipher_serv_ptr->service_hdl = args->cipher_hdl;
		*cipher_hdl = cipher_serv_ptr->service_hdl;
	} while (false);

	return err;
}

hsm_err_t hsm_close_cipher_service(hsm_hdl_t cipher_hdl)
{
	struct hsm_service_hdl_s *serv_ptr;
	int32_t error = 1;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t rsp_code;

	do {
		serv_ptr = service_hdl_to_ptr(cipher_hdl);
		if (serv_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		error = process_sab_msg(serv_ptr->session->phdl,
					serv_ptr->session->mu_type,
					SAB_CIPHER_CLOSE_REQ,
					MT_SAB_CIPHER,
					(uint32_t)cipher_hdl,
					NULL, &rsp_code);

		if (error == 0) {
			err = sab_rating_to_hsm_err(rsp_code);
		}
		delete_service(serv_ptr);
	} while (false);

	return err;
}

hsm_err_t hsm_cipher_one_go(hsm_hdl_t cipher_hdl, op_cipher_one_go_args_t *args)
{
	struct hsm_service_hdl_s *serv_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t error;
	uint32_t rsp_code;

	do {
		serv_ptr = service_hdl_to_ptr(cipher_hdl);
		if (serv_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		error = process_sab_msg(serv_ptr->session->phdl,
					serv_ptr->session->mu_type,
					SAB_CIPHER_ONE_GO_REQ,
					MT_SAB_CIPHER,
					(uint32_t)cipher_hdl,
					args, &rsp_code);

		if (rsp_code || (error != 0))
			printf("SAB_ONE_GO_CIPHER: SAB FW Error[0x%x]:"\
				"SAB Engine Error[0x%x]\n", rsp_code, error);

		err = sab_rating_to_hsm_err(rsp_code);
	} while (false);

	return err;
}
