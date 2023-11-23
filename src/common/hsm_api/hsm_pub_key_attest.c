// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_pub_key_attest.h"
#include "internal/hsm_sign_gen.h"

#include "sab_process_msg.h"

hsm_err_t hsm_pub_key_attest(hsm_hdl_t signature_gen_hdl,
			     op_pub_key_attest_args_t *args)
{
	uint32_t error;
	struct hsm_service_hdl_s *serv_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	do {
		if (!args)
			break;

		if (!signature_gen_hdl) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		serv_ptr = service_hdl_to_ptr(signature_gen_hdl);
		if (!serv_ptr) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		error = process_sab_msg(serv_ptr->session->phdl,
					serv_ptr->session->mu_type,
					SAB_PUB_KEY_ATTEST_REQ,
					MT_SAB_PUB_KEY_ATTEST,
					(uint32_t)signature_gen_hdl,
					args, &rsp_code);

		err = sab_rating_to_hsm_err(error);
		if (err != HSM_NO_ERROR) {
			se_err("HSM Error: SAB_PUB_KEY_ATTEST_REQ [0x%x].\n", err);
			break;
		}

		err = sab_rating_to_hsm_err(rsp_code);
		if (err != HSM_NO_ERROR)
			se_err("HSM RSP Error: SAB_PUB_KEY_ATTEST_REQ [0x%x].\n", err);

	} while (false);

	return err;
}

hsm_err_t hsm_do_pub_key_attest(hsm_hdl_t key_store_hdl,
				op_pub_key_attest_args_t *args)
{
	hsm_err_t hsmret;
	/* Stores the error status of the main operation.
	 */
	hsm_err_t op_err;
	hsm_hdl_t sig_gen_hdl = 0;
	open_svc_sign_gen_args_t open_sig_gen_args = {0};

	op_err = hsm_open_signature_generation_service(key_store_hdl,
						       &open_sig_gen_args,
						       &sig_gen_hdl);
	if (op_err) {
		se_err("hsm_open_signature_generation_service ret:0x%x\n",
		       op_err);
		goto exit;
	}

	op_err = hsm_pub_key_attest(sig_gen_hdl, args);
	if (op_err)
		se_err("hsm_pub_key_attest ret:0x%x\n", op_err);

	hsmret = hsm_close_signature_generation_service(sig_gen_hdl);
	if (hsmret) {
		se_err("hsm_close_signature_generation_service ret:0x%x\n",
		       hsmret);
		if (op_err == HSM_NO_ERROR)
			op_err = hsmret;
	}

exit:
	return op_err;
}
