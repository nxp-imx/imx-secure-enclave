// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2019-2023 NXP
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
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;
	uint32_t error;

	do {
		if ((args == NULL) || (cipher_hdl == NULL)) {
			break;
		}

		if (!key_store_hdl) {
			err = HSM_UNKNOWN_HANDLE;
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

		err = sab_rating_to_hsm_err(error, key_store_serv_ptr->session->phdl);

		if (err != HSM_NO_ERROR) {
			se_err("HSM Error: SAB_CIPHER_OPEN_REQ [0x%x].\n", err);
			break;
		}
		err = sab_rating_to_hsm_err(rsp_code, key_store_serv_ptr->session->phdl);
		if (err != HSM_NO_ERROR) {
			se_err("HSM RSP Error: SAB_CIPHER_OPEN_REQ [0x%x].\n",
				err);
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
	uint32_t error;
	hsm_err_t err = HSM_UNKNOWN_HANDLE;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	do {
		if (!cipher_hdl)
			break;

		serv_ptr = service_hdl_to_ptr(cipher_hdl);

		if (!serv_ptr)
			break;

		error = process_sab_msg(serv_ptr->session->phdl,
					serv_ptr->session->mu_type,
					SAB_CIPHER_CLOSE_REQ,
					MT_SAB_CIPHER,
					(uint32_t)cipher_hdl,
					NULL, &rsp_code);

		err = sab_rating_to_hsm_err(error, serv_ptr->session->phdl);

		if (err != HSM_NO_ERROR) {
			se_err("HSM Error: SAB_CIPHER_CLOSE_REQ [0x%x].\n", err);
			break;
		}
		err = sab_rating_to_hsm_err(rsp_code, serv_ptr->session->phdl);
		if (err != HSM_NO_ERROR) {
			se_err("HSM RSP Error: SAB_CIPHER_CLOSE_REQ [0x%x].\n",
				err);
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
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	do {
		if (!args)
			break;

		if (!cipher_hdl) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

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

		err = sab_rating_to_hsm_err(error, serv_ptr->session->phdl);

		if (err != HSM_NO_ERROR) {
			se_err("HSM Error: SAB_CIPHER_ONE_GO_REQ [0x%x].\n", err);
			break;
		}
		err = sab_rating_to_hsm_err(rsp_code, serv_ptr->session->phdl);
		if (err != HSM_NO_ERROR) {
			se_err("HSM RSP Error: SAB_CIPHER_ONE_GO_REQ [0x%x].\n",
				err);
		}

	} while (false);

	return err;
}

hsm_err_t hsm_do_cipher(hsm_hdl_t key_store_hdl, op_cipher_one_go_args_t *cipher_args)
{
	hsm_hdl_t cipher_hdl = 0;
	hsm_err_t err;
	/* Stores the error status of the main operation.
	 */
	hsm_err_t op_err;
	open_svc_cipher_args_t open_cipher_args = {0};

	open_cipher_args.flags = cipher_args->svc_flags;

	op_err = hsm_open_cipher_service(key_store_hdl, &open_cipher_args, &cipher_hdl);
	if (op_err) {
		se_err("hsm_open_cipher_service ret:0x%x\n", op_err);
		goto exit;
	}

	op_err = hsm_cipher_one_go(cipher_hdl, cipher_args);
	if (op_err)
		se_err("hsm_cipher_one_go ret:0x%x\n", op_err);

	err = hsm_close_cipher_service(cipher_hdl);
	if (err) {
		se_err("hsm_close_cipher_service ret:0x%x\n", err);
		if (op_err == HSM_NO_ERROR)
			op_err = err;
	}

exit:

	return op_err;
}
