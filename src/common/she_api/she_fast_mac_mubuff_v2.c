// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#include "she_api.h"
#include "sab_process_msg.h"
#include "sab_common_err.h"

she_err_t she_verify_fast_mac_mubuff_v2(she_hdl_t utils_handle,
					op_verify_mac_t *args)
{
	struct she_service_hdl_s *serv_ptr;
	she_err_t err = SHE_GENERAL_ERROR;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;
	op_fast_mac_mubuff_t mac_args = {0};
	uint32_t ret, lib_err;
	uint64_t temp;

	if (!args || !utils_handle) {
		se_err("Invalid Input parameters\n");
		return err;
	}

	serv_ptr = she_service_hdl_to_ptr(utils_handle);
	if (!serv_ptr) {
		se_err("Service pointer not found\n");
		return err;
	}

	args->verification_status = SHE_MAC_VERIFICATION_FAILED;
	mac_args.key_id = args->key_ext | args->key_id;
	mac_args.data_length = args->message_length;
	mac_args.mac_length = args->mac_length * 8;
	mac_args.flags = SHE_FAST_MAC_FLAGS_VERIFICATION;

	/*
	 * Input message is stored at offset 16 if MAC is of 0 length
	 * else concatenate MAC and message
	 */
	if (args->mac_length == 0u) {
		ret = plat_os_abs_data_buf_v2(serv_ptr->session->phdl,
					      &temp,
					      args->mac,
					      SHE_MAC_SIZE,
					      DATA_BUF_IS_INPUT |
					      DATA_BUF_SHE_V2X);
	} else {
		ret = plat_os_abs_data_buf_v2(serv_ptr->session->phdl,
					      &temp,
					      args->mac,
					      args->mac_length,
					      DATA_BUF_IS_INPUT |
					      DATA_BUF_SHE_V2X);
	}

	err = plat_err_to_she_err(SAB_FAST_MAC_REQ,
				  ret,
				  SHE_PREPARE);
	if (err != SHE_NO_ERROR)
		return err;

	ret = plat_os_abs_data_buf_v2(serv_ptr->session->phdl,
				      &temp,
				      args->message,
				      args->message_length,
				      DATA_BUF_IS_INPUT |
				      DATA_BUF_SHE_V2X);

	err = plat_err_to_she_err(SAB_FAST_MAC_REQ,
				  ret,
				  SHE_PREPARE);
	if (err != SHE_NO_ERROR)
		return err;

	lib_err = process_sab_msg(serv_ptr->session->phdl,
				  serv_ptr->session->mu_type,
				  SAB_SHE_FAST_MAC_MUBUFF_V2_REQ,
				  MT_SAB_FAST_MAC,
				  serv_ptr->service_hdl,
				  &mac_args, &rsp_code);

	serv_ptr->session->last_rating = rsp_code;

	err = lib_err_to_she_err(lib_err);

	if (err != SHE_NO_ERROR) {
		se_err("SHE Err: SAB_SHE_FAST_MAC_MUBUFF_V2_REQ (Verify) [0x%x]\n", err);
		return err;
	}

	err = sab_rating_to_she_err(rsp_code, serv_ptr->session->phdl);

	if (err != SHE_NO_ERROR) {
		se_err("SHE RSP Error: SAB_SHE_FAST_MAC_MUBUFF_V2_REQ (Verify) [0x%x]\n",
		       err);
		return err;
	}

	if (mac_args.verification_status == SHE_FAST_MAC_VERIFICATION_STATUS_OK)
		args->verification_status = SHE_MAC_VERIFICATION_SUCCESS;
	else
		args->verification_status = SHE_MAC_VERIFICATION_FAILED;

	return err;
}

she_err_t she_generate_fast_mac_mubuff_v2(she_hdl_t utils_handle,
					  op_generate_mac_t *args)
{
	struct she_service_hdl_s *serv_ptr;
	she_err_t err = SHE_GENERAL_ERROR;
	uint32_t lib_err;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;
	op_fast_mac_mubuff_t mac_args = {0};
	uint32_t ret;
	uint64_t temp;

	if (!args || !utils_handle) {
		se_err("Invalid Input parameters\n");
		return err;
	}

	serv_ptr = she_service_hdl_to_ptr(utils_handle);
	if (!serv_ptr) {
		se_err("Service pointer not found\n");
		return err;
	}

	mac_args.key_id = args->key_ext | args->key_id;
	mac_args.data_length = args->message_length;
	mac_args.mac_length = 0u;
	mac_args.flags = SHE_FAST_MAC_FLAGS_GENERATION;

	/* Input message is stored at offset 16 and MAC will come at offset 0*/
	ret = plat_os_abs_data_buf_v2(serv_ptr->session->phdl,
				      &temp,
				      args->mac,
				      SHE_MAC_SIZE,
				      DATA_BUF_SHE_V2X);

	err = plat_err_to_she_err(SAB_FAST_MAC_REQ,
				  ret,
				  SHE_PREPARE);
	if (err != SHE_NO_ERROR)
		return err;

	ret = plat_os_abs_data_buf_v2(serv_ptr->session->phdl,
				      &temp,
				      args->message,
				      args->message_length,
				      DATA_BUF_IS_INPUT |
				      DATA_BUF_SHE_V2X);

	err = plat_err_to_she_err(SAB_FAST_MAC_REQ,
				  ret,
				  SHE_PREPARE);
	if (err != SHE_NO_ERROR)
		return err;

	lib_err = process_sab_msg(serv_ptr->session->phdl,
				  serv_ptr->session->mu_type,
				  SAB_SHE_FAST_MAC_MUBUFF_V2_REQ,
				  MT_SAB_FAST_MAC,
				  serv_ptr->service_hdl,
				  &mac_args, &rsp_code);

	serv_ptr->session->last_rating = rsp_code;

	err = lib_err_to_she_err(lib_err);

	if (err != SHE_NO_ERROR) {
		se_err("SHE Error: SAB_SHE_FAST_MAC_MUBUFF_V2_REQ [0x%x].\n", err);
		return err;
	}

	err = sab_rating_to_she_err(rsp_code, serv_ptr->session->phdl);

	if (err != SHE_NO_ERROR) {
		se_err("SHE RSP Error: SAB_SHE_FAST_MAC_MUBUFF_V2_REQ [0x%x].\n", err);
		return err;
	}

	return err;
}
