// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "she_api.h"
#include "sab_process_msg.h"

#ifndef PSA_COMPLIANT
she_err_t she_extend_seed(she_hdl_t session_hdl, op_rng_extend_seed_t *args)
{
	uint32_t error;
	struct she_hdl_s *hdl;
	she_err_t err = SHE_GENERAL_ERROR;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	if (!args) {
		se_err("args cannot be NULL\n");
		return err;
	}

	if (!session_hdl || !args->entropy_size) {
		se_err("Incorrect input parameters\n");
		return err;
	}

	hdl = she_session_hdl_to_ptr(session_hdl);
	if (!hdl || !hdl->rng_handle) {
		se_err("Handle not found\n");
		return SHE_RNG_SEED;
	}

	error = process_sab_msg(hdl->phdl,
				hdl->mu_type,
				SAB_RNG_EXTEND_SEED,
				MT_SAB_RNG,
				hdl->rng_handle,
				args,
				&rsp_code);

	err = sab_rating_to_she_err(error);

	if (err != SHE_NO_ERROR) {
		se_err("SHE Error: SAB_RNG_EXTEND_SEED [0x%x].\n", err);
		return err;
	}

	err = sab_rating_to_she_err(rsp_code);

	if (err != SHE_NO_ERROR)
		se_err("SHE RSP Error: SAB_RNG_EXTEND_SEED [0x%x].\n", err);

	return err;
}
#endif

she_err_t she_get_random(she_hdl_t session_hdl, op_get_random_args_t *args)
{
	uint32_t error;
	struct she_hdl_s *hdl;
	she_err_t err = SHE_GENERAL_ERROR;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	if (!args) {
		se_err("args cannot be NULL\n");
		return err;
	}

	if (!session_hdl) {
		se_err("Session handle cannot be NULL\n");
		return err;
	}

	hdl = she_session_hdl_to_ptr(session_hdl);
	if (!hdl || !hdl->rng_handle) {
		se_err("Handle not found\n");
		return SHE_SEQUENCE_ERROR;
	}

	error = process_sab_msg(hdl->phdl,
				hdl->mu_type,
				SAB_RNG_GET_RANDOM,
				MT_SAB_RNG,
				hdl->rng_handle,
				args,
				&rsp_code);

	err = sab_rating_to_she_err(error);

	if (err != SHE_NO_ERROR) {
		se_err("SHE Error: SAB_RNG_GET_RANDOM [0x%x].\n", err);
		return err;
	}

	err = sab_rating_to_she_err(rsp_code);

	if (err != SHE_NO_ERROR)
		se_err("SHE RSP Error: SAB_RNG_GET_RANDOM [0x%x].\n", err);

	return err;
}

#ifndef PSA_COMPLIANT
she_err_t she_open_rng_service(she_hdl_t session_hdl,
			       open_svc_rng_args_t *args)
{
	uint32_t error;
	struct she_hdl_s *hdl;
	she_err_t err = SHE_GENERAL_ERROR;
	uint32_t sab_err;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	if (!args) {
		se_err("args cannot be NULL\n");
		return err;
	}

	if (!session_hdl) {
		se_err("Session handle cannot be NULL\n");
		return err;
	}

	hdl = she_session_hdl_to_ptr(session_hdl);
	if (!hdl) {
		se_err("Handle not found\n");
		return err;
	}

	error = process_sab_msg(hdl->phdl,
				hdl->mu_type,
				SAB_RNG_OPEN_REQ,
				MT_SAB_RNG,
				(uint32_t)session_hdl,
				args, &rsp_code);

	err = sab_rating_to_she_err(error);

	if (err != SHE_NO_ERROR) {
		se_err("SHE Error: SAB_RNG_OPEN_REQ [0x%x].\n", err);
		return err;
	}

	err = sab_rating_to_she_err(rsp_code);

	if (err != SHE_NO_ERROR) {
		se_err("SHE RSP Error: SAB_RNG_OPEN_REQ [0x%x].\n", err);
		return err;
	}

	hdl->rng_handle = args->rng_hdl;

	return err;
}

she_err_t she_close_rng_service(she_hdl_t session_hdl)
{
	uint32_t error;
	struct she_hdl_s *hdl;
	she_err_t err = SHE_GENERAL_ERROR;
	uint32_t sab_err;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	if (!session_hdl) {
		se_err("Session handle cannot be NULL\n");
		return err;
	}

	hdl = she_session_hdl_to_ptr(session_hdl);
	if (!hdl || !hdl->rng_handle) {
		se_err("Handle not found\n");
		return err;
	}

	error = process_sab_msg(hdl->phdl,
				hdl->mu_type,
				SAB_RNG_CLOSE_REQ,
				MT_SAB_RNG,
				hdl->rng_handle,
				NULL,
				&rsp_code);

	err = sab_rating_to_she_err(error);

	if (err != SHE_NO_ERROR) {
		se_err("SHE Error: SAB_RNG_CLOE_REQ [0x%x].\n", err);
		return err;
	}

	err = sab_rating_to_she_err(rsp_code);

	if (err != SHE_NO_ERROR)
		se_err("SHE RSP Error: SAB_RNG_CLOSE_REQ [0x%x].\n", err);

	hdl->rng_handle = 0;

	return err;
}
#endif

