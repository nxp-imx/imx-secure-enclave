// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "she_api.h"
#include "sab_process_msg.h"

she_err_t she_open_cipher_service(she_hdl_t key_store_handle,
				  open_svc_cipher_args_t *args)
{
	struct she_service_hdl_s *serv_ptr;
	struct she_service_hdl_s *serv_ptr_1;
	she_err_t err = SHE_GENERAL_ERROR;
	uint32_t sab_err;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	if (!args || !key_store_handle) {
		se_err("args/key store handle cannot be NULL\n");
		return err;
	}

	serv_ptr = she_service_hdl_to_ptr(key_store_handle);
	if (!serv_ptr) {
		se_err("Handle pointer not found\n");
		return err;
	}

	serv_ptr_1 = add_she_service(serv_ptr->session);
	if (!serv_ptr_1)
		return err;

	sab_err = process_sab_msg(serv_ptr->session->phdl,
				  serv_ptr->session->mu_type,
				  SAB_CIPHER_OPEN_REQ,
				  MT_SAB_CIPHER,
				  key_store_handle,
				  args,
				  &rsp_code);

	serv_ptr->session->last_rating = rsp_code;

	err = sab_rating_to_she_err(sab_err, serv_ptr->session->phdl);

	if (err != SHE_NO_ERROR) {
		se_err("SHE Error: SAB_CIPHER_OPEN_REQ [0x%x].\n", err);
		delete_she_service(serv_ptr_1);
		return err;
	}

	err = sab_rating_to_she_err(rsp_code, serv_ptr->session->phdl);

	if (err != SHE_NO_ERROR) {
		se_err("SHE RSP Error: SAB_CIPHER_OPEN_REQ [0x%x].\n", err);
		delete_she_service(serv_ptr_1);
		return err;
	}

	serv_ptr_1->service_hdl = args->cipher_hdl;
	return err;
}

she_err_t she_close_cipher_service(she_hdl_t cipher_handle)
{
	struct she_service_hdl_s *serv_ptr;
	she_err_t err = SHE_GENERAL_ERROR;
	uint32_t sab_err;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	serv_ptr = she_service_hdl_to_ptr(cipher_handle);
	if (!serv_ptr) {
		se_err("service pointer not found\n");
		return err;
	}

	sab_err = process_sab_msg(serv_ptr->session->phdl,
				  serv_ptr->session->mu_type,
				  SAB_CIPHER_CLOSE_REQ,
				  MT_SAB_CIPHER,
				  cipher_handle,
				  NULL,
				  &rsp_code);

	serv_ptr->session->last_rating = rsp_code;

	err = sab_rating_to_she_err(sab_err, serv_ptr->session->phdl);

	if (err != SHE_NO_ERROR) {
		se_err("SHE Error: SAB_CIPHER_CLOSE_REQ [0x%x].\n", err);
		return err;
	}
	err = sab_rating_to_she_err(rsp_code, serv_ptr->session->phdl);
	if (err != SHE_NO_ERROR) {
		se_err("SHE RSP Error: SAB_CIPHER_CLOSE_REQ [0x%x].\n", err);
		return err;
	}

	delete_she_service(serv_ptr);

	return err;
}

she_err_t she_cipher_one_go(she_hdl_t cipher_handle, op_cipher_one_go_args_t *args)
{
	struct she_service_hdl_s *serv_ptr;
	she_err_t err = SHE_GENERAL_ERROR;
	uint32_t sab_err;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	if (!args || !cipher_handle) {
		se_err("Invalid input parameters\n");
		return err;
	}

	serv_ptr = she_service_hdl_to_ptr(cipher_handle);
	if (!serv_ptr) {
		se_err("Service pointer not found\n");
		return err;
	}

	sab_err = process_sab_msg(serv_ptr->session->phdl,
				  serv_ptr->session->mu_type,
				  SAB_CIPHER_ONE_GO_REQ,
				  MT_SAB_CIPHER,
				  (uint32_t)cipher_handle,
				  args,
				  &rsp_code);

	serv_ptr->session->last_rating = rsp_code;

	err = sab_rating_to_she_err(sab_err, serv_ptr->session->phdl);

	if (err != SHE_NO_ERROR) {
		se_err("SHE Error: SAB_CIPHER_ONE_GO_REQ [0x%x].\n", err);
		return err;
	}

	err = sab_rating_to_she_err(rsp_code, serv_ptr->session->phdl);

	if (err != SHE_NO_ERROR) {
		se_err("SHE RSP Error: SAB_CIPHER_ONE_GO_REQ [0x%x].\n", err);
		return err;
	}

	return err;
}
