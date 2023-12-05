// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <stdio.h>

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_sm2_eces.h"

#include "sab_process_msg.h"

hsm_err_t hsm_open_sm2_eces_service(hsm_hdl_t key_store_hdl,
				    open_svc_sm2_eces_args_t *args,
				    hsm_hdl_t *sm2_eces_hdl)
{
	struct hsm_service_hdl_s *key_store_serv_ptr;
	struct hsm_service_hdl_s *sm2_eces_serv_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;
	uint32_t sab_err;

	do {
		if (!args || !sm2_eces_hdl)
			break;

		key_store_serv_ptr = service_hdl_to_ptr(key_store_hdl);
		if (!key_store_serv_ptr) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		sm2_eces_serv_ptr = add_service(key_store_serv_ptr->session);
		if (!sm2_eces_serv_ptr)
			break;

		sab_err = process_sab_msg(key_store_serv_ptr->session->phdl,
					  key_store_serv_ptr->session->mu_type,
					  SAB_SM2_ECES_DEC_OPEN_REQ,
					  MT_SAB_SM2_ECES,
					  (uint32_t)key_store_hdl,
					  args,
					  &rsp_code);

		err = sab_rating_to_hsm_err(sab_err, key_store_serv_ptr->session->phdl);
		if (err != HSM_NO_ERROR) {
			se_err("HSM Error: SAB_SM2_ECES_DEC_OPEN_REQ [0x%x].\n", err);
			delete_service(sm2_eces_serv_ptr);
			break;
		}

		err = sab_rating_to_hsm_err(rsp_code, key_store_serv_ptr->session->phdl);
		if (err != HSM_NO_ERROR) {
			se_err("HSM RSP Error: SAB_SM2_ECES_DEC_OPEN_REQ [0x%x].\n", err);
			delete_service(sm2_eces_serv_ptr);
			break;
		}
		sm2_eces_serv_ptr->service_hdl = args->sm2_eces_hdl;
		*sm2_eces_hdl = sm2_eces_serv_ptr->service_hdl;
	} while (false);

	return err;
}

hsm_err_t hsm_close_sm2_eces_service(hsm_hdl_t sm2_eces_hdl)
{
	struct hsm_service_hdl_s *serv_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;
	uint32_t sab_err;

	do {
		if (!sm2_eces_hdl)
			break;

		serv_ptr = service_hdl_to_ptr(sm2_eces_hdl);
		if (!serv_ptr) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		sab_err = process_sab_msg(serv_ptr->session->phdl,
					  serv_ptr->session->mu_type,
					  SAB_SM2_ECES_DEC_CLOSE_REQ,
					  MT_SAB_SM2_ECES,
					  (uint32_t)sm2_eces_hdl,
					  NULL,
					  &rsp_code);

		err = sab_rating_to_hsm_err(sab_err, serv_ptr->session->phdl);
		if (err != HSM_NO_ERROR) {
			se_err("HSM Error: SAB_SM2_ECES_DEC_CLOSE_REQ [0x%x].\n", err);
			break;
		}

		err = sab_rating_to_hsm_err(rsp_code, serv_ptr->session->phdl);
		if (err != HSM_NO_ERROR) {
			se_err("HSM RSP Error:SAB_SM2_ECES_DEC_CLOSE_REQ [0x%x].\n", err);
			break;
		}

		delete_service(serv_ptr);
	} while (false);

	return err;
}

hsm_err_t hsm_sm2_eces_encryption(hsm_hdl_t session_hdl, op_sm2_eces_enc_args_t *args)
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
					  SAB_SM2_ECES_ENC_REQ,
					  MT_SAB_SM2_ECES,
					  (uint32_t)session_hdl,
					  args,
					  &rsp_code);

		err = sab_rating_to_hsm_err(sab_err, sess_ptr->phdl);
		if (err != HSM_NO_ERROR) {
			se_err("HSM Error: SAB_SM2_ECES_ENC_REQ [0x%x].\n", err);
			break;
		}

		err = sab_rating_to_hsm_err(rsp_code, sess_ptr->phdl);
		if (err != HSM_NO_ERROR) {
			se_err("HSM RSP Error: SAB_SM2_ECES_ENC_REQ [0x%x].\n", err);
			break;
		}

	} while (false);

	return err;
}

hsm_err_t hsm_sm2_eces_decryption(hsm_hdl_t sm2_eces_hdl, op_sm2_eces_dec_args_t *args)
{
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;
	uint32_t sab_err;
	struct hsm_service_hdl_s *serv_ptr;

	do {
		if (!args || !sm2_eces_hdl)
			break;

		serv_ptr = service_hdl_to_ptr(sm2_eces_hdl);
		if (!serv_ptr) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		sab_err = process_sab_msg(serv_ptr->session->phdl,
					  serv_ptr->session->mu_type,
					  SAB_SM2_ECES_DEC_REQ,
					  MT_SAB_SM2_ECES,
					  (uint32_t)sm2_eces_hdl,
					  args,
					  &rsp_code);

		err = sab_rating_to_hsm_err(sab_err, serv_ptr->session->phdl);
		if (err != HSM_NO_ERROR) {
			se_err("HSM Error: SAB_SM2_ECES_DEC_REQ [0x%x].\n", err);
			break;
		}

		err = sab_rating_to_hsm_err(rsp_code, serv_ptr->session->phdl);
		if (err != HSM_NO_ERROR) {
			se_err("HSM RSP Error: SAB_SM2_ECES_DEC_REQ [0x%x].\n", err);
			break;
		}

	} while (false);

	return err;
}
