// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#include "she_api.h"
#include "sab_process_msg.h"

she_err_t she_mac_one_go(she_hdl_t mac_hdl,
			 op_mac_one_go_args_t *args,
			 she_mac_verification_status_t *status)
{
	struct she_service_hdl_s *serv_ptr;
	she_err_t err = SHE_GENERAL_ERROR;
	uint32_t sab_err;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	if ((se_get_soc_id() == SOC_IMX8DXL && se_get_board_type() == IMX8DXL_DL1) ||
	    (se_get_soc_id() == SOC_IMX8DXL && se_get_board_type() == IMX8DXL_DL2) ||
	    se_get_soc_id() == SOC_IMX8QXP)
		return SHE_FEATURE_NOT_SUPPORTED;

	if (!args || !mac_hdl || !status) {
		se_err("Invalid input parameters\n");
		return err;
	}

	serv_ptr = she_service_hdl_to_ptr(mac_hdl);
	if (!serv_ptr) {
		se_err("Service pointer not found\n");
		return err;
	}

	sab_err = process_sab_msg(serv_ptr->session->phdl,
				  serv_ptr->session->mu_type,
				  SAB_MAC_REQ,
				  MT_SAB_MAC,
				  (uint32_t)mac_hdl,
				  args,
				  &rsp_code);

	serv_ptr->session->last_rating = rsp_code;

	err = lib_err_to_she_err(sab_err);

	if (err != SHE_NO_ERROR) {
		se_err("SHE Error: SAB_MAC_ONE_GO_REQ [0x%x].\n", err);
		return err;
	}

	err = sab_rating_to_she_err(rsp_code, serv_ptr->session->phdl);

	if (err != SHE_NO_ERROR) {
		se_err("SHE RSP Error: SAB_MAC_ONE_GO_REQ [0x%x].\n", err);
		return err;
	}

	*status = args->verification_status;

	return err;
}

she_err_t she_open_mac_service(she_hdl_t key_store_handle,
			       open_svc_mac_args_t *args)
{
	struct she_service_hdl_s *serv_ptr;
	struct she_service_hdl_s *serv_ptr_1;
	she_err_t err = SHE_GENERAL_ERROR;
	uint32_t sab_err;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	if ((se_get_soc_id() == SOC_IMX8DXL && se_get_board_type() == IMX8DXL_DL1) ||
	    (se_get_soc_id() == SOC_IMX8DXL && se_get_board_type() == IMX8DXL_DL2) ||
	    se_get_soc_id() == SOC_IMX8QXP)
		return SHE_FEATURE_NOT_SUPPORTED;

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
				  SAB_MAC_OPEN_REQ,
				  MT_SAB_MAC,
				  key_store_handle,
				  args,
				  &rsp_code);

	serv_ptr->session->last_rating = rsp_code;

	err = lib_err_to_she_err(sab_err);
	if (err != SHE_NO_ERROR) {
		se_err("SHE Error: SAB_MAC_OPEN_REQ [0x%x].\n", err);
		delete_she_service(serv_ptr_1);
		return err;
	}

	err = sab_rating_to_she_err(rsp_code, serv_ptr->session->phdl);

	if (err != SHE_NO_ERROR) {
		se_err("SHE RSP Error: SAB_MAC_OPEN_REQ [0x%x].\n", err);
		delete_she_service(serv_ptr_1);
		return err;
	}

	serv_ptr_1->service_hdl = args->mac_serv_hdl;
	return err;
}

she_err_t she_close_mac_service(she_hdl_t mac_hdl)
{
	struct she_service_hdl_s *serv_ptr;
	she_err_t err = SHE_GENERAL_ERROR;
	uint32_t sab_err;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	if ((se_get_soc_id() == SOC_IMX8DXL && se_get_board_type() == IMX8DXL_DL1) ||
	    (se_get_soc_id() == SOC_IMX8DXL && se_get_board_type() == IMX8DXL_DL2) ||
	    se_get_soc_id() == SOC_IMX8QXP)
		return SHE_FEATURE_NOT_SUPPORTED;

	serv_ptr = she_service_hdl_to_ptr(mac_hdl);
	if (!serv_ptr) {
		se_err("service pointer not found\n");
		return err;
	}

	sab_err = process_sab_msg(serv_ptr->session->phdl,
				  serv_ptr->session->mu_type,
				  SAB_MAC_CLOSE_REQ,
				  MT_SAB_MAC,
				  mac_hdl,
				  NULL,
				  &rsp_code);

	serv_ptr->session->last_rating = rsp_code;

	err = lib_err_to_she_err(sab_err);
	if (err != SHE_NO_ERROR) {
		se_err("SHE Error: SAB_MAC_CLOSE_REQ [0x%x].\n", err);
		return err;
	}

	err = sab_rating_to_she_err(rsp_code, serv_ptr->session->phdl);

	if (err != SHE_NO_ERROR) {
		se_err("SHE RSP Error: SAB_MAC_CLOSE_REQ [0x%x].\n", err);
		return err;
	}

	delete_she_service(serv_ptr);

	return err;
}
