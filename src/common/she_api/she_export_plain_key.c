// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "she_api.h"
#include "sab_process_msg.h"

she_err_t she_export_plain_key(she_hdl_t utils_handle,
			       op_export_plain_key_args_t *args)
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
				  SAB_SHE_PLAIN_KEY_EXPORT,
				  MT_SAB_PLAIN_KEY,
				  (uint32_t)utils_handle,
				  args, &rsp_code);

	serv_ptr->session->last_rating = rsp_code;

	err = sab_rating_to_she_err(sab_err, serv_ptr->session->phdl);

	if (err != SHE_NO_ERROR) {
		se_err("SHE Error: SAB_SHE_PLAIN_KEY_EXPORT [0x%x].\n", err);
		return err;
	}

	err = sab_rating_to_she_err(rsp_code, serv_ptr->session->phdl);

	if (err != SHE_NO_ERROR) {
		se_err("SHE RSP Error: SAB_SHE_PLAIN_KEY_EXPORT [0x%x].\n", err);
		return err;
	}

	return err;
}
