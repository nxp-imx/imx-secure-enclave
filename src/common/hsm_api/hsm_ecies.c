// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <stdio.h>

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_ecies.h"

#include "sab_process_msg.h"

hsm_err_t hsm_ecies_encryption(hsm_hdl_t session_hdl, op_ecies_enc_args_t *args)
{
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;
	uint32_t sab_err;
	struct hsm_session_hdl_s *sess_ptr;

	do {
		if (!args || !session_hdl)
			break;

		sess_ptr = session_hdl_to_ptr(session_hdl);
		if (!sess_ptr) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		sab_err = process_sab_msg(sess_ptr->phdl,
					  sess_ptr->mu_type,
					  SAB_ECIES_ENC_REQ,
					  MT_SAB_ECIES,
					  (uint32_t)session_hdl,
					  args,
					  &rsp_code);

		err = sab_rating_to_hsm_err(sab_err, sess_ptr->phdl);
		if (err != HSM_NO_ERROR) {
			se_err("HSM Error: SAB_ECIES_ENC_REQ [0x%x].\n", err);
			break;
		}

		err = sab_rating_to_hsm_err(rsp_code, sess_ptr->phdl);
		if (err != HSM_NO_ERROR) {
			se_err("HSM RSP Error: SAB_ECIES_ENC_REQ [0x%x].\n", err);
			break;
		}

	} while (false);

	return err;
}

hsm_err_t hsm_ecies_decryption(hsm_hdl_t cipher_hdl, op_ecies_dec_args_t *args)
{
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;
	uint32_t sab_err;
	struct hsm_service_hdl_s *serv_ptr;

	do {
		if (!args || !cipher_hdl)
			break;

		serv_ptr = service_hdl_to_ptr(cipher_hdl);
		if (!serv_ptr) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		sab_err = process_sab_msg(serv_ptr->session->phdl,
					  serv_ptr->session->mu_type,
					  SAB_CIPHER_ECIES_DECRYPT_REQ,
					  MT_SAB_ECIES,
					  (uint32_t)cipher_hdl,
					  args,
					  &rsp_code);

		err = sab_rating_to_hsm_err(sab_err, serv_ptr->session->phdl);
		if (err != HSM_NO_ERROR) {
			se_err("HSM Error: SAB_CIPHER_ECIES_DECRYPT_REQ [0x%x].\n", err);
			break;
		}

		err = sab_rating_to_hsm_err(rsp_code, serv_ptr->session->phdl);
		if (err != HSM_NO_ERROR) {
			se_err("HSM RSP Error: SAB_ECIES_DECRYPT_REQ [0x%x].\n", err);
			break;
		}

	} while (false);

	return err;
}
