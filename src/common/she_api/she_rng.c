// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "she_api.h"
#include "sab_process_msg.h"

#ifndef PSA_COMPLIANT
she_err_t she_extend_seed(she_hdl_t rng_handle, op_rng_extend_seed_t *args)
{
	struct she_service_hdl_s *serv_ptr;
	she_err_t err = SHE_GENERAL_ERROR;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;
	uint32_t error;

	if (!args) {
		se_err("args cannot be NULL\n");
		return err;
	}

	if (!rng_handle || !args->entropy_size) {
		se_err("Incorrect input parameters\n");
		return err;
	}

	serv_ptr = she_service_hdl_to_ptr(rng_handle);
	if (!serv_ptr) {
		se_err("Service pointer not found\n");
		return err;
	}

	error = process_sab_msg(serv_ptr->session->phdl,
				serv_ptr->session->mu_type,
				SAB_RNG_EXTEND_SEED,
				MT_SAB_RNG,
				rng_handle,
				args,
				&rsp_code);

	serv_ptr->session->last_rating = rsp_code;

	err = sab_rating_to_she_err(error, serv_ptr->session->phdl);

	if (err != SHE_NO_ERROR) {
		se_err("SHE Error: SAB_RNG_EXTEND_SEED [0x%x].\n", err);
		return err;
	}

	err = sab_rating_to_she_err(rsp_code, serv_ptr->session->phdl);

	if (err != SHE_NO_ERROR)
		se_err("SHE RSP Error: SAB_RNG_EXTEND_SEED [0x%x].\n", err);

	return err;
}
#endif

she_err_t she_get_random(she_hdl_t rng_handle, op_get_random_args_t *args)
{
	struct she_service_hdl_s *serv_ptr;
	she_err_t err = SHE_GENERAL_ERROR;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;
	uint32_t error;

	if (!args) {
		se_err("args cannot be NULL\n");
		return err;
	}

	if (!rng_handle) {
		se_err("RNG handle cannot be NULL\n");
		return err;
	}

	serv_ptr = she_service_hdl_to_ptr(rng_handle);
	if (!serv_ptr) {
		se_err("Service pointer not found\n");
		return err;
	}

	error = process_sab_msg(serv_ptr->session->phdl,
				serv_ptr->session->mu_type,
				SAB_RNG_GET_RANDOM,
				MT_SAB_RNG,
				rng_handle,
				args,
				&rsp_code);

	serv_ptr->session->last_rating = rsp_code;

	err = sab_rating_to_she_err(error, serv_ptr->session->phdl);

	if (err != SHE_NO_ERROR) {
		se_err("SHE Error: SAB_RNG_GET_RANDOM [0x%x].\n", err);
		return err;
	}

	err = sab_rating_to_she_err(rsp_code, serv_ptr->session->phdl);

	if (err != SHE_NO_ERROR)
		se_err("SHE RSP Error: SAB_RNG_GET_RANDOM [0x%x].\n", err);

	return err;
}

#ifndef PSA_COMPLIANT
she_err_t she_open_rng_service(she_hdl_t session_hdl,
			       open_svc_rng_args_t *args)
{
	struct she_session_hdl_s *sess_ptr;
	struct she_service_hdl_s *serv_ptr;
	she_err_t err = SHE_GENERAL_ERROR;
	uint32_t sab_err;
	uint32_t error;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	if (!args) {
		se_err("args cannot be NULL\n");
		return err;
	}

	if (!session_hdl) {
		se_err("Session handle cannot be NULL\n");
		return err;
	}

	sess_ptr = she_session_hdl_to_ptr(session_hdl);
	if (!sess_ptr) {
		se_err("Handle pointer not found\n");
		return err;
	}

	serv_ptr = add_she_service(sess_ptr);
	if (!serv_ptr) {
		se_err("Service pointer not found\n");
		return err;
	}

	error = process_sab_msg(sess_ptr->phdl,
				sess_ptr->mu_type,
				SAB_RNG_OPEN_REQ,
				MT_SAB_RNG,
				(uint32_t)session_hdl,
				args, &rsp_code);

	sess_ptr->last_rating = rsp_code;

	err = sab_rating_to_she_err(error, sess_ptr->phdl);

	if (err != SHE_NO_ERROR) {
		se_err("SHE Error: SAB_RNG_OPEN_REQ [0x%x].\n", err);
		delete_she_service(serv_ptr);
		return err;
	}

	err = sab_rating_to_she_err(rsp_code, sess_ptr->phdl);

	if (err != SHE_NO_ERROR) {
		se_err("SHE RSP Error: SAB_RNG_OPEN_REQ [0x%x].\n", err);
		delete_she_service(serv_ptr);
		return err;
	}

	serv_ptr->service_hdl = args->rng_hdl;

	return err;
}

she_err_t she_close_rng_service(she_hdl_t rng_handle)
{
	struct she_service_hdl_s *serv_ptr;
	she_err_t err = SHE_GENERAL_ERROR;
	uint32_t sab_err;
	uint32_t error;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	if (!rng_handle) {
		se_err("RNG handle cannot be NULL\n");
		return err;
	}

	serv_ptr = she_service_hdl_to_ptr(rng_handle);
	if (!serv_ptr) {
		se_err("Service pointer not found\n");
		return err;
	}

	error = process_sab_msg(serv_ptr->session->phdl,
				serv_ptr->session->mu_type,
				SAB_RNG_CLOSE_REQ,
				MT_SAB_RNG,
				rng_handle,
				NULL,
				&rsp_code);

	serv_ptr->session->last_rating = rsp_code;

	err = sab_rating_to_she_err(error, serv_ptr->session->phdl);

	if (err != SHE_NO_ERROR) {
		se_err("SHE Error: SAB_RNG_CLOE_REQ [0x%x].\n", err);
		return err;
	}

	err = sab_rating_to_she_err(rsp_code, serv_ptr->session->phdl);

	if (err != SHE_NO_ERROR)
		se_err("SHE RSP Error: SAB_RNG_CLOSE_REQ [0x%x].\n", err);

	delete_she_service(serv_ptr);

	return err;
}
#endif

