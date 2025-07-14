// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023, 2025 NXP
 */

#include "she_api.h"
#include "sab_process_msg.h"

she_err_t she_key_update(she_hdl_t utils_handle, op_key_update_args_t *args)
{
	struct she_service_hdl_s *serv_ptr;
	she_err_t err = SHE_GENERAL_ERROR;
	op_get_info_args_t iargs = {0};
	uint32_t sab_err;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	if (!args || !utils_handle) {
		se_err("Invalid Input parameters\n");
		return err;
	}

	serv_ptr = she_service_hdl_to_ptr(utils_handle);
	if (!serv_ptr) {
		se_err("Service pointer not found\n");
		return err;
	}

	if (args->m1_size != SHE_KEY_SIZE_IN_BYTES ||
	    args->m2_size != 2 * SHE_KEY_SIZE_IN_BYTES ||
	    args->m3_size != SHE_KEY_SIZE_IN_BYTES ||
	    args->m4_size != 2 * SHE_KEY_SIZE_IN_BYTES ||
	    args->m5_size != SHE_KEY_SIZE_IN_BYTES) {
		se_err("Invalid Input size\n");
		return err;
	}

	she_get_info(serv_ptr->session->session_hdl, &iargs);

	printf("chip_monotonic_counter 0x%x\n", iargs.chip_monotonic_counter);

	if (!iargs.chip_monotonic_counter) {
		if (!args->flag) {
			se_err("Monotonic counter will not be enabled, flag is not set\n");
			return err;
		}
		se_err("Incrementing the monotonic counter will be enforced\n");
		se_err("from now onwards, even if the flag is set or not.\n");
	}

	sab_err = process_sab_msg(serv_ptr->session->phdl,
				  serv_ptr->session->mu_type,
				  SAB_SHE_KEY_UPDATE,
				  MT_SAB_KEY_UPDATE,
				  (uint32_t)utils_handle,
				  args, &rsp_code);

	serv_ptr->session->last_rating = rsp_code;

	err = sab_rating_to_she_err(sab_err, serv_ptr->session->phdl);

	if (err != SHE_NO_ERROR) {
		se_err("SHE Error: SAB_SHE_KEY_UPDATE [0x%x].\n", err);
		return err;
	}

	err = sab_rating_to_she_err(rsp_code, serv_ptr->session->phdl);

	if (err != SHE_NO_ERROR) {
		se_err("SHE RSP Error: SAB_SHE_KEY_UPDATE [0x%x].\n", err);
		return err;
	}

	return err;
}

she_err_t she_key_update_ext(she_hdl_t utils_handle, op_key_update_ext_args_t *args)
{
	struct she_service_hdl_s *serv_ptr;
	she_err_t err = SHE_GENERAL_ERROR;
	uint32_t sab_err;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	if (!args || !utils_handle) {
		se_err("Invalid Input parameters\n");
		return err;
	}

	serv_ptr = she_service_hdl_to_ptr(utils_handle);
	if (!serv_ptr) {
		se_err("Service pointer not found\n");
		return err;
	}

	if (args->m1_size != SHE_KEY_SIZE_IN_BYTES ||
	    args->m2_size != 2 * SHE_KEY_SIZE_IN_BYTES ||
	    args->m3_size != SHE_KEY_SIZE_IN_BYTES ||
	    args->m4_size != 2 * SHE_KEY_SIZE_IN_BYTES ||
	    args->m5_size != SHE_KEY_SIZE_IN_BYTES) {
		se_err("Invalid Input size\n");
		return err;
	}

	sab_err = process_sab_msg(serv_ptr->session->phdl,
				  serv_ptr->session->mu_type,
				  SAB_SHE_KEY_UPDATE_EXT,
				  MT_SAB_KEY_UPDATE,
				  (uint32_t)utils_handle,
				  args, &rsp_code);

	serv_ptr->session->last_rating = rsp_code;

	err = sab_rating_to_she_err(sab_err, serv_ptr->session->phdl);

	if (err != SHE_NO_ERROR) {
		se_err("SHE Error: SAB_SHE_KEY_UPDATE_EXT [0x%x].\n", err);
		return err;
	}

	err = sab_rating_to_she_err(rsp_code, serv_ptr->session->phdl);

	if (err != SHE_NO_ERROR) {
		se_err("SHE RSP Error: SAB_SHE_KEY_UPDATE_EXT [0x%x].\n", err);
		return err;
	}

	return err;
}
