// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "she_api.h"
#include "sab_process_msg.h"

she_err_t she_open_utils(she_hdl_t key_store_handle, op_open_utils_args_t *args)
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

	/* Get the access to SHE utils */
	sab_err = process_sab_msg(serv_ptr->session->phdl,
				  serv_ptr->session->mu_type,
				  SAB_SHE_UTILS_OPEN,
				  MT_SAB_UTILS,
				  (uint32_t)key_store_handle,
				  args,
				  &rsp_code);

	serv_ptr->session->last_rating = rsp_code;

	err = sab_rating_to_she_err(sab_err, serv_ptr->session->phdl);

	if (err != SHE_NO_ERROR) {
		se_err("SHE Error: SAB_SHE_UTILS_OPEN [0x%x].\n", err);
		delete_she_service(serv_ptr_1);
		return err;
	}

	err = sab_rating_to_she_err(rsp_code, serv_ptr->session->phdl);

	if (err != SHE_NO_ERROR) {
		se_err("SHE RSP Error: SAB_SHE_UTILS_OPEN [0x%x].\n", err);
		delete_she_service(serv_ptr_1);
		return err;
	}

	serv_ptr_1->service_hdl = args->utils_handle;

	return err;
}

she_err_t she_close_utils(she_hdl_t utils_handle)
{
	struct she_service_hdl_s *serv_ptr;
	she_err_t err = SHE_GENERAL_ERROR;
	uint32_t sab_err;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	serv_ptr = she_service_hdl_to_ptr(utils_handle);
	if (!serv_ptr) {
		se_err("Service pointer not found\n");
		return err;
	}

	sab_err = process_sab_msg(serv_ptr->session->phdl,
				  serv_ptr->session->mu_type,
				  SAB_SHE_UTILS_CLOSE,
				  MT_SAB_UTILS,
				  (uint32_t)utils_handle,
				  NULL,
				  &rsp_code);

	serv_ptr->session->last_rating = rsp_code;

	err = sab_rating_to_she_err(sab_err, serv_ptr->session->phdl);

	if (err != SHE_NO_ERROR) {
		se_err("SHE Error: SAB_SHE_UTILS_CLOSE [0x%x].\n", err);
		return err;
	}
	err = sab_rating_to_she_err(rsp_code, serv_ptr->session->phdl);
	if (err != SHE_NO_ERROR) {
		se_err("SHE RSP Error: SAB_SHE_UTILS_CLOSE [0x%x].\n", err);
		return err;
	}

	delete_she_service(serv_ptr);

	return err;
}
