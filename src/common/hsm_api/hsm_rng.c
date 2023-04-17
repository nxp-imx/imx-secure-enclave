// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2019-2023 NXP
 */

#include <stdio.h>

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_rng.h"

#include "sab_process_msg.h"

hsm_err_t hsm_get_random(hsm_hdl_t rng_hdl, op_get_random_args_t *args)
{
	uint32_t error;
#ifndef PSA_COMPLIANT
	struct hsm_service_hdl_s *serv_ptr;
#endif
	struct hsm_session_hdl_s *sess_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	do {
		if (args == NULL) {
			break;
		}
#ifndef PSA_COMPLIANT
		serv_ptr = service_hdl_to_ptr(rng_hdl);
		if (serv_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}
		sess_ptr = serv_ptr->session;
#else
		/* For PSA compliant RNG API needs
		 * to use session handle.
		 */

		if (!rng_hdl) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		sess_ptr = session_hdl_to_ptr(rng_hdl);
		if (sess_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}
#endif
		error = process_sab_msg(sess_ptr->phdl,
					sess_ptr->mu_type,
					SAB_RNG_GET_RANDOM,
					MT_SAB_RNG,
					(uint32_t)rng_hdl,
					args, &rsp_code);

		err = sab_rating_to_hsm_err(error);

		if (err != HSM_NO_ERROR) {
			se_err("HSM Error: SAB_RNG_GET_RANDOM [0x%x].\n", err);
			break;
		}

		err = sab_rating_to_hsm_err(rsp_code);

		if (err != HSM_NO_ERROR) {
			se_err("HSM RSP Error: SAB_RNG_GET_RANDOM [0x%x].\n", err);
		}

	} while (false);

	return err;
}

#ifndef PSA_COMPLIANT
hsm_err_t hsm_open_rng_service(hsm_hdl_t session_hdl,
				open_svc_rng_args_t *args,
				hsm_hdl_t *rng_hdl)
{
	uint32_t error;
	struct hsm_session_hdl_s *sess_ptr;
	struct hsm_service_hdl_s *serv_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t sab_err;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	do {
		if ((args == NULL) || (rng_hdl == NULL)) {
			break;
		}

		if (!session_hdl) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		sess_ptr = session_hdl_to_ptr(session_hdl);
		if (sess_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		serv_ptr = add_service(sess_ptr);
		if (serv_ptr == NULL) {
			break;
		}

		error = process_sab_msg(sess_ptr->phdl,
					sess_ptr->mu_type,
					SAB_RNG_OPEN_REQ,
					MT_SAB_RNG,
					(uint32_t)session_hdl,
					args, &rsp_code);

		err = sab_rating_to_hsm_err(error);

		if (err != HSM_NO_ERROR) {
			se_err("HSM Error: SAB_RNG_OPEN_REQ [0x%x].\n", err);
			delete_service(serv_ptr);
			break;
		}

		err = sab_rating_to_hsm_err(rsp_code);

		if (err != HSM_NO_ERROR) {
			se_err("HSM RSP Error: SAB_RNG_OPEN_REQ [0x%x].\n", err);
			delete_service(serv_ptr);
			break;
		}

		*rng_hdl = args->rng_hdl;
	} while (false);

	return err;
}

hsm_err_t hsm_close_rng_service(hsm_hdl_t rng_hdl)
{
	struct hsm_service_hdl_s *serv_ptr;
	uint32_t error;
	hsm_err_t err = HSM_UNKNOWN_HANDLE;
	uint32_t sab_err;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	do {
		if (!rng_hdl)
			break;

		serv_ptr = service_hdl_to_ptr(rng_hdl);

		if (!serv_ptr)
			break;

		error = process_sab_msg(serv_ptr->session->phdl,
					serv_ptr->session->mu_type,
					SAB_RNG_CLOSE_REQ,
					MT_SAB_RNG,
					(uint32_t)rng_hdl,
					NULL, &rsp_code);

		err = sab_rating_to_hsm_err(error);

		if (err != HSM_NO_ERROR) {
			se_err("HSM Error: SAB_RNG_CLOE_REQ [0x%x].\n", err);
			break;
		}

		err = sab_rating_to_hsm_err(rsp_code);

		if (err != HSM_NO_ERROR) {
			se_err("HSM RSP Error: SAB_RNG_CLOSE_REQ [0x%x].\n", err);
		}

		delete_service(serv_ptr);
	} while (false);

	return err;
}
#endif

hsm_err_t hsm_do_rng(hsm_hdl_t session_hdl, op_get_random_args_t *rng_get_random_args)
{
#ifndef PSA_COMPLIANT
	hsm_err_t err;
#endif
	/* Stores the error status of the main operation.
	 */
	hsm_err_t op_err;
#ifndef PSA_COMPLIANT
	open_svc_rng_args_t rng_srv_args = {0};
	hsm_hdl_t rng_serv_hdl = 0;

	rng_srv_args.flags = rng_get_random_args->svc_flags;

	op_err = hsm_open_rng_service(session_hdl, &rng_srv_args, &rng_serv_hdl);
	if (op_err) {
		se_err("Error[0x%x]: RNG Service Open failed [0x%08x].\n",
							op_err, rng_serv_hdl);
		goto exit;
	}
	op_err =  hsm_get_random(rng_serv_hdl, rng_get_random_args);
#else
	op_err =  hsm_get_random(session_hdl, rng_get_random_args);
#endif
	if (op_err) {
		se_err("Error[0x%x]: RNG failed for size =%d.\n",
				op_err, rng_get_random_args->random_size);
	}

#ifndef PSA_COMPLIANT
	err = hsm_close_rng_service(rng_serv_hdl);
	if (err) {
		se_err("Error[0x%x]: RNG Service Close failed [0x%08x].\n",
							err, rng_serv_hdl);
		if (op_err == HSM_NO_ERROR)
			op_err = err;
	}
exit:
#endif
	return op_err;
}
