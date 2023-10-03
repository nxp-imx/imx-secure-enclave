// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "she_api.h"
#include "sab_process_msg.h"
#include "sab_common_err.h"

she_err_t she_verify_mac_v2x(struct she_service_hdl_s *serv_ptr,
			     op_verify_mac_t *args)
{
	she_err_t err = SHE_GENERAL_ERROR;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;
	op_fast_v2x_mac_t mac_args = {0};
	uint32_t ret, lib_err;
	uint64_t temp;

	args->verification_status = SHE_MAC_VERIFICATION_FAILED;
	mac_args.key_id = args->key_ext | args->key_id;
	mac_args.data_length = args->message_length;
	mac_args.mac_length = args->mac_length * 8;
	mac_args.flags = SHE_FAST_MAC_FLAGS_VERIFICATION;

	mac_args.m1 = args->message[0] + (args->message[1] << 8) +
		      (args->message[2] << 16) + (args->message[3] << 24);
	mac_args.m2 = args->message[4] + (args->message[5] << 8) +
		      (args->message[6] << 16) + (args->message[7] << 24);
	mac_args.m3 = args->message[8] + (args->message[9] << 8) +
		      (args->message[10] << 16) + (args->message[11] << 24);
	mac_args.m4 = args->message[12] + (args->message[13] << 8) +
		      (args->message[14] << 16) + (args->message[15] << 24);

	ret = plat_os_abs_data_buf_v2(serv_ptr->session->phdl,
				      &temp,
				      args->mac,
				      SHE_MAC_SIZE,
				      DATA_BUF_IS_INPUT | DATA_BUF_SHE_V2X);

	err = plat_err_to_she_err(SAB_SHE_FAST_MAC_MUBUFF_REQ,
				  ret,
				  SHE_PREPARE);
	if (err != SHE_NO_ERROR)
		return err;

	lib_err = process_sab_msg(serv_ptr->session->phdl,
				  serv_ptr->session->mu_type,
				  SAB_SHE_FAST_MAC_MUBUFF_REQ,
				  MT_SAB_FAST_MAC,
				  serv_ptr->service_hdl,
				  &mac_args, &rsp_code);

	serv_ptr->session->last_rating = rsp_code;

	err = lib_err_to_she_err(lib_err);

	if (err != SHE_NO_ERROR) {
		se_err("SHE Error: SAB_SHE_FAST_MAC_MUBUFF_REQ [0x%x].\n", err);
		return err;
	}

	err = sab_rating_to_she_err(rsp_code);

	if (err != SHE_NO_ERROR) {
		se_err("SHE RSP Error: SAB_SHE_FAST_MAC_MUBUFF_REQ [0x%x].\n", err);
		return err;
	}

	if (mac_args.verification_status == SHE_FAST_MAC_VERIFICATION_STATUS_OK)
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
	op_fast_seco_mac_t mac_args = {0};
	uint32_t ret, lib_err;
	uint64_t temp;

	args->verification_status = SHE_MAC_VERIFICATION_FAILED;
	mac_args.key_id = args->key_ext | args->key_id;
	mac_args.data_length = args->message_length;
	mac_args.mac_length = args->mac_length;
	mac_args.flags = SHE_FAST_MAC_FLAGS_VERIFICATION;

	/* the MAC data is stored right after the input data */
	if (args->message_length == 0u) {
		ret = plat_os_abs_data_buf_v2(serv_ptr->session->phdl,
					      &temp,
					      args->mac,
					      SHE_MAC_SIZE,
					      DATA_BUF_IS_INPUT |
					      DATA_BUF_USE_SEC_MEM |
					      DATA_BUF_SHORT_ADDR);
		mac_args.data_offset = temp & SEC_MEM_SHORT_ADDR_MASK;
	} else {
		ret = plat_os_abs_data_buf_v2(serv_ptr->session->phdl,
					      &temp,
					      args->message,
					      args->message_length,
					      DATA_BUF_IS_INPUT |
					      DATA_BUF_USE_SEC_MEM |
					      DATA_BUF_SHORT_ADDR);

		err = plat_err_to_she_err(SAB_FAST_MAC_REQ,
					  ret,
					  SHE_PREPARE);
		if (err != SHE_NO_ERROR)
			return err;

		mac_args.data_offset = temp & SEC_MEM_SHORT_ADDR_MASK;

		ret = plat_os_abs_data_buf_v2(serv_ptr->session->phdl,
					      &temp,
					      args->mac,
					      SHE_MAC_SIZE,
					      DATA_BUF_IS_INPUT |
					      DATA_BUF_USE_SEC_MEM |
					      DATA_BUF_SHORT_ADDR);
	}

	err = plat_err_to_she_err(SAB_FAST_MAC_REQ,
				  ret,
				  SHE_PREPARE);
	if (err != SHE_NO_ERROR)
		return err;

	if (args->mac_length_encoding == MAC_BITS_LENGTH)
		mac_args.flags |= SHE_FAST_MAC_FLAGS_VERIF_BIT_LEN;

	lib_err = process_sab_msg(serv_ptr->session->phdl,
				  serv_ptr->session->mu_type,
				  SAB_FAST_MAC_REQ,
				  MT_SAB_FAST_MAC,
				  serv_ptr->service_hdl,
				  &mac_args, &rsp_code);

	serv_ptr->session->last_rating = rsp_code;

	err = lib_err_to_she_err(lib_err);

	if (err != SHE_NO_ERROR) {
		se_err("SHE Error: SAB_FAST_MAC_REQ (Verify) [0x%x].\n", err);
		return err;
	}

	err = sab_rating_to_she_err(rsp_code);

	if (err != SHE_NO_ERROR) {
		se_err("SHE RSP Error: SAB_FAST_MAC_REQ (Verify) [0x%x].\n", err);
		return err;
	}

	if (mac_args.verification_status == SHE_FAST_MAC_VERIFICATION_STATUS_OK)
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
	op_fast_v2x_mac_t mac_args = {0};
	uint32_t ret;
	uint64_t temp;

	mac_args.key_id = args->key_ext | args->key_id;
	mac_args.data_length = args->message_length;
	mac_args.m1 = args->message[0] + (args->message[1] << 8) +
		      (args->message[2] << 16) + (args->message[3] << 24);
	mac_args.m2 = args->message[4] + (args->message[5] << 8) +
		      (args->message[6] << 16) + (args->message[7] << 24);
	mac_args.m3 = args->message[8] + (args->message[9] << 8) +
		      (args->message[10] << 16) + (args->message[11] << 24);
	mac_args.m4 = args->message[12] + (args->message[13] << 8) +
		      (args->message[14] << 16) + (args->message[15] << 24);

	mac_args.mac_length = 0u;
	mac_args.flags = SHE_FAST_MAC_FLAGS_GENERATION;

	ret = plat_os_abs_data_buf_v2(serv_ptr->session->phdl,
				      &temp,
				      args->mac,
				      SHE_MAC_SIZE,
				      DATA_BUF_SHE_V2X);

	err = plat_err_to_she_err(SAB_SHE_FAST_MAC_MUBUFF_REQ,
				  ret,
				  SHE_PREPARE);
	if (err != SHE_NO_ERROR)
		return err;

	lib_err = process_sab_msg(serv_ptr->session->phdl,
				  serv_ptr->session->mu_type,
				  SAB_SHE_FAST_MAC_MUBUFF_REQ,
				  MT_SAB_FAST_MAC,
				  serv_ptr->service_hdl,
				  &mac_args, &rsp_code);

	serv_ptr->session->last_rating = rsp_code;

	err = lib_err_to_she_err(lib_err);

	if (err != SHE_NO_ERROR) {
		se_err("SHE Error: SAB_SHE_FAST_MAC_MUBUFF_REQ [0x%x].\n", err);
		return err;
	}

	err = sab_rating_to_she_err(rsp_code);

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
	op_fast_seco_mac_t mac_args = {0};
	uint32_t ret;
	uint64_t temp;

	mac_args.key_id = args->key_ext | args->key_id;
	mac_args.data_length = args->message_length;
	mac_args.mac_length = 0u;
	mac_args.flags = SHE_FAST_MAC_FLAGS_GENERATION;

	/* the MAC data is stored right after the input data */
	if (args->message_length == 0u) {
		ret = plat_os_abs_data_buf_v2(serv_ptr->session->phdl,
					      &temp,
					      args->mac,
					      SHE_MAC_SIZE,
					      DATA_BUF_USE_SEC_MEM |
					      DATA_BUF_SHORT_ADDR);
		mac_args.data_offset = temp & SEC_MEM_SHORT_ADDR_MASK;
	} else {
		ret = plat_os_abs_data_buf_v2(serv_ptr->session->phdl,
					      &temp,
					      args->message,
					      args->message_length,
					      DATA_BUF_IS_INPUT |
					      DATA_BUF_USE_SEC_MEM |
					      DATA_BUF_SHORT_ADDR);

		err = plat_err_to_she_err(SAB_FAST_MAC_REQ,
					  ret,
					  SHE_PREPARE);
		if (err != SHE_NO_ERROR)
			return err;

		mac_args.data_offset = temp & SEC_MEM_SHORT_ADDR_MASK;

		ret = plat_os_abs_data_buf_v2(serv_ptr->session->phdl,
					      &temp,
					      args->mac,
					      SHE_MAC_SIZE,
					      DATA_BUF_USE_SEC_MEM |
					      DATA_BUF_SHORT_ADDR);
	}

	err = plat_err_to_she_err(SAB_FAST_MAC_REQ,
				  ret,
				  SHE_PREPARE);
	if (err != SHE_NO_ERROR)
		return err;

	lib_err = process_sab_msg(serv_ptr->session->phdl,
				  serv_ptr->session->mu_type,
				  SAB_FAST_MAC_REQ,
				  MT_SAB_FAST_MAC,
				  serv_ptr->service_hdl,
				  &mac_args, &rsp_code);

	serv_ptr->session->last_rating = rsp_code;

	err = lib_err_to_she_err(lib_err);

	if (err != SHE_NO_ERROR) {
		se_err("SHE Error: SAB_FAST_MAC_REQ [0x%x].\n", err);
		return err;
	}

	err = sab_rating_to_she_err(rsp_code);

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
