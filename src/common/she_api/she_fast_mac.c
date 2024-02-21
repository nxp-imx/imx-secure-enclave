// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#include "she_api.h"
#include "sab_process_msg.h"
#include "sab_common_err.h"

she_err_t she_verify_mac_v2x(struct she_service_hdl_s *serv_ptr,
			     op_verify_mac_t *args)
{
	she_err_t err = SHE_GENERAL_ERROR;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;
	uint32_t lib_err;

	args->verification_status = SHE_MAC_VERIFICATION_FAILED;
	args->flags = SHE_FAST_MAC_FLAGS_VERIFICATION;

	lib_err = process_sab_msg(serv_ptr->session->phdl,
				  serv_ptr->session->mu_type,
				  SAB_SHE_FAST_MAC_MUBUFF_REQ,
				  MT_SAB_FAST_MAC_MUBUFF,
				  serv_ptr->service_hdl,
				  args, &rsp_code);

	serv_ptr->session->last_rating = rsp_code;

	err = lib_err_to_she_err(lib_err);

	if (err != SHE_NO_ERROR) {
		se_err("SHE Error: SAB_SHE_FAST_MAC_MUBUFF_REQ [0x%x].\n", err);
		return err;
	}

	err = sab_rating_to_she_err(rsp_code, serv_ptr->session->phdl);

	if (err != SHE_NO_ERROR) {
		se_err("SHE RSP Error: SAB_SHE_FAST_MAC_MUBUFF_REQ [0x%x].\n", err);
		return err;
	}

	if (args->verification_status == SHE_FAST_MAC_VERIFICATION_STATUS_OK)
		args->verification_status = SHE_MAC_VERIFICATION_SUCCESS;
	else
		args->verification_status = SHE_MAC_VERIFICATION_FAILED;

	return err;
}

she_err_t she_verify_mac_seco(struct she_service_hdl_s *serv_ptr,
			      op_verify_mac_t *args)
{
	she_err_t err = SHE_GENERAL_ERROR;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;
	uint32_t lib_err;

	args->verification_status = SHE_MAC_VERIFICATION_FAILED;
	args->flags = SHE_FAST_MAC_FLAGS_VERIFICATION;

	if (args->mac_length_encoding == MAC_BITS_LENGTH)
		args->flags |= SHE_FAST_MAC_FLAGS_VERIF_BIT_LEN;

	lib_err = process_sab_msg(serv_ptr->session->phdl,
				  serv_ptr->session->mu_type,
				  SAB_FAST_MAC_REQ,
				  MT_SAB_FAST_MAC,
				  serv_ptr->service_hdl,
				  args, &rsp_code);

	serv_ptr->session->last_rating = rsp_code;

	err = lib_err_to_she_err(lib_err);

	if (err != SHE_NO_ERROR) {
		se_err("SHE Error: SAB_FAST_MAC_REQ (Verify) [0x%x].\n", err);
		return err;
	}

	err = sab_rating_to_she_err(rsp_code, serv_ptr->session->phdl);

	if (err != SHE_NO_ERROR) {
		se_err("SHE RSP Error: SAB_FAST_MAC_REQ (Verify) [0x%x].\n", err);
		return err;
	}

	if (args->verification_status == SHE_FAST_MAC_VERIFICATION_STATUS_OK)
		args->verification_status = SHE_MAC_VERIFICATION_SUCCESS;
	else
		args->verification_status = SHE_MAC_VERIFICATION_FAILED;

	return err;
}

she_err_t she_verify_mac(she_hdl_t utils_handle,
			 op_verify_mac_t *args)
{
	struct she_service_hdl_s *serv_ptr;
	she_err_t err = SHE_GENERAL_ERROR;

	if (!args || !utils_handle) {
		se_err("Invalid Input parameters\n");
		return err;
	}

	serv_ptr = she_service_hdl_to_ptr(utils_handle);
	if (!serv_ptr) {
		se_err("Service pointer not found\n");
		return err;
	}

	if (she_v2x_mu)
		err = she_verify_mac_v2x(serv_ptr, args);
	else
		err = she_verify_mac_seco(serv_ptr, args);

	return err;
}

she_err_t she_generate_mac_v2x(struct she_service_hdl_s *serv_ptr,
			       op_generate_mac_t *args)
{
	uint32_t lib_err;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;
	she_err_t err = SHE_GENERAL_ERROR;

	args->flags = SHE_FAST_MAC_FLAGS_GENERATION;

	lib_err = process_sab_msg(serv_ptr->session->phdl,
				  serv_ptr->session->mu_type,
				  SAB_SHE_FAST_MAC_MUBUFF_REQ,
				  MT_SAB_FAST_MAC_MUBUFF,
				  serv_ptr->service_hdl,
				  args, &rsp_code);

	serv_ptr->session->last_rating = rsp_code;

	err = lib_err_to_she_err(lib_err);

	if (err != SHE_NO_ERROR) {
		se_err("SHE Error: SAB_SHE_FAST_MAC_MUBUFF_REQ [0x%x].\n", err);
		return err;
	}

	err = sab_rating_to_she_err(rsp_code, serv_ptr->session->phdl);

	if (err != SHE_NO_ERROR) {
		se_err("SHE RSP Error: SAB_SHE_FAST_MAC_MUBUFF_REQ [0x%x].\n", err);
		return err;
	}

	return err;
}

she_err_t she_generate_mac_seco(struct she_service_hdl_s *serv_ptr,
				op_generate_mac_t *args)
{
	uint32_t lib_err;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;
	she_err_t err = SHE_GENERAL_ERROR;

	args->flags = SHE_FAST_MAC_FLAGS_GENERATION;

	lib_err = process_sab_msg(serv_ptr->session->phdl,
				  serv_ptr->session->mu_type,
				  SAB_FAST_MAC_REQ,
				  MT_SAB_FAST_MAC,
				  serv_ptr->service_hdl,
				  args, &rsp_code);

	serv_ptr->session->last_rating = rsp_code;

	err = lib_err_to_she_err(lib_err);

	if (err != SHE_NO_ERROR) {
		se_err("SHE Error: SAB_FAST_MAC_REQ [0x%x].\n", err);
		return err;
	}

	err = sab_rating_to_she_err(rsp_code, serv_ptr->session->phdl);

	if (err != SHE_NO_ERROR) {
		se_err("SHE RSP Error: SAB_FAST_MAC_REQ [0x%x].\n", err);
		return err;
	}

	return err;
}

she_err_t she_generate_mac(she_hdl_t utils_handle,
			   op_generate_mac_t *args)
{
	struct she_service_hdl_s *serv_ptr;
	she_err_t err = SHE_GENERAL_ERROR;

	if (!args || !utils_handle) {
		se_err("Invalid Input parameters\n");
		return err;
	}

	serv_ptr = she_service_hdl_to_ptr(utils_handle);
	if (!serv_ptr) {
		se_err("Service pointer not found\n");
		return err;
	}

	if (she_v2x_mu)
		err = she_generate_mac_v2x(serv_ptr, args);
	else
		err = she_generate_mac_seco(serv_ptr, args);

	return err;
}
