// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024, 2026 NXP
 */

#include <stdio.h>

#include "common/se_lib_service.h"
#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_key_store.h"

#include "plat_utils.h"
#include "sab_process_msg.h"
#include "se_lib_serv_intern.h"

static hsm_err_t exchange_key_store_open_msg(struct plat_os_abs_hdl *phdl,
					     uint32_t mu_type,
					     hsm_hdl_t session_hdl,
					     void *args)
{
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;
	hsm_err_t err;
	uint32_t lib_err;

	lib_err = process_sab_msg(phdl, mu_type,
				  SAB_KEY_STORE_OPEN_REQ,
				  MT_SAB_KEY_STORE,
				  session_hdl,
				  args, &rsp_code);

	err = lib_err_to_hsm_err(lib_err);
	if (err == HSM_NO_ERROR)
		err = sab_rating_to_hsm_err(rsp_code, phdl);

	return err;
}

hsm_err_t hsm_open_key_store_service(hsm_hdl_t session_hdl,
				     open_svc_key_store_args_t *args,
				     hsm_hdl_t *key_store_hdl)
{
	struct hsm_session_hdl_s *sess_ptr;
	struct hsm_service_hdl_s *serv_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;
#ifndef PSA_COMPLIANT
	uint32_t lib_err;
#endif

	do {
		if (!args || !key_store_hdl)
			break;

		if (!session_hdl) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		sess_ptr = session_hdl_to_ptr(session_hdl);
		if (!sess_ptr) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		serv_ptr = add_service(sess_ptr);
		if (!serv_ptr)
			break;
#ifndef PSA_COMPLIANT
		/* Send the signed message to platform if provided here. */
		if (args->signed_message) {
			lib_err = plat_os_abs_send_signed_message_v2
					(serv_ptr->session->phdl,
					 args->signed_message,
					 args->signed_msg_size);

			err = plat_err_to_hsm_err(SAB_KEY_STORE_OPEN_REQ,
						  lib_err,
						  HSM_PREPARE);

			if (err != HSM_NO_ERROR)
				break;
		}
#endif
		err = exchange_key_store_open_msg(serv_ptr->session->phdl,
						  serv_ptr->session->mu_type,
						  session_hdl, args);

		if (err != HSM_NO_ERROR) {
			se_err("HSM RSP Error: SAB_KEY_STORE_OPEN_REQ [0x%x].\n",
			       err);
			delete_service(serv_ptr);
			break;
		}

		serv_ptr->service_hdl = args->key_store_hdl;
		*key_store_hdl = serv_ptr->service_hdl;
	} while (false);

	return err;
}

hsm_err_t hsm_close_key_store_service(hsm_hdl_t key_store_hdl)
{
	struct hsm_service_hdl_s *serv_ptr;
	hsm_err_t err = HSM_UNKNOWN_HANDLE;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;
	uint32_t lib_err;

	do {
		if (!key_store_hdl)
			break;

		serv_ptr = service_hdl_to_ptr(key_store_hdl);

		if (!serv_ptr)
			break;

		lib_err = process_sab_msg(serv_ptr->session->phdl,
					  serv_ptr->session->mu_type,
					  SAB_KEY_STORE_CLOSE_REQ,
					  MT_SAB_KEY_STORE,
					  (uint32_t)key_store_hdl,
					  NULL,
					  &rsp_code);

		err = lib_err_to_hsm_err(lib_err);
		if (err != HSM_NO_ERROR)
			break;

		err = sab_rating_to_hsm_err(rsp_code, serv_ptr->session->phdl);

		if (err != HSM_NO_ERROR)
			se_err("HSM RSP Error: SAB_KEY_STORE_CLOSE_REQ [0x%x].\n",
			       err);

		/*
		 * Do not delete the service if SAB_ERR is 0x0429.
		 * i.e. in case of HSM_INVALID_PARAM (0x04)
		 */
		if (err != HSM_INVALID_PARAM)
			delete_service(serv_ptr);

	} while (false);

	return err;
}

hsm_err_t hsm_key_store_reprov_en(hsm_hdl_t session_hdl,
				  op_key_store_reprov_en_args_t *args)
{
	hsm_err_t err = HSM_GENERAL_ERROR;
	struct hsm_session_hdl_s *sess_ptr;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;
	uint32_t lib_err;

	do {
		if (!args)
			break;

		if (!session_hdl) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		sess_ptr = session_hdl_to_ptr(session_hdl);
		if (!sess_ptr) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		lib_err = process_sab_msg(sess_ptr->phdl,
					  sess_ptr->mu_type,
					  SAB_KEY_STORE_REPROV_EN_REQ,
					  MT_SAB_KEY_STORE_REPROV_EN,
					  (uint32_t)session_hdl,
					  args,
					  &rsp_code);

		err = lib_err_to_hsm_err(lib_err);
		if (err != HSM_NO_ERROR)
			break;

		err = sab_rating_to_hsm_err(rsp_code, sess_ptr->phdl);

		if (err != HSM_NO_ERROR) {
			se_err("HSM RSP Error: SAB_KEY_STORE_REPROV_EN_REQ [0x%x].\n",
			       err);
			break;
		}
	} while (false);

	return err;
}

#ifdef PSA_COMPLIANT
hsm_err_t hsm_get_key_store_status(hsm_hdl_t session_hdl,
				   uint32_t key_store_id,
				   op_key_store_status_args_t *args)
{
	hsm_err_t err = HSM_GENERAL_ERROR;
	struct hsm_session_hdl_s *sess_ptr;
	open_svc_key_store_args_t key_store_args = {0};
	uint32_t status;

	do {
		if (!args)
			break;

		if (!session_hdl) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		sess_ptr = session_hdl_to_ptr(session_hdl);
		if (!sess_ptr) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		key_store_args.key_store_identifier = key_store_id;
		key_store_args.flags = HSM_SVC_KEY_STORE_FLAGS_KEY_STORE_STATUS;

		err = exchange_key_store_open_msg(sess_ptr->phdl, sess_ptr->mu_type,
						  session_hdl, &key_store_args);

		if (err != HSM_NO_ERROR) {
			se_err("%s RSP Error: SAB_KEY_STORE_OPEN_REQ [0x%x].\n",
			       "HSM GET KEY STORE STATUS", err);
			break;
		}

		/* The command had flag HSM_SVC_KEY_STORE_FLAGS_KEY_STORE_STATUS
		 * set, so key_store_handle field actually contains the key status
		 */
		status = key_store_args.key_store_hdl;

		/* Decode key store status, and populate the status structure args */
		args->exist_status = HSM_KEY_STORE_STATUS_EXIST(status);
		args->open_status = HSM_KEY_STORE_STATUS_OPEN(status);
		args->num_keys_status = HSM_KEY_STORE_STATUS_NUM_KEYS(status);
		args->num_sess_status = HSM_KEY_STORE_STATUS_NUM_SESS(status);

	} while (false);

	return err;
}

hsm_err_t hsm_get_storage_status(hsm_hdl_t session_hdl, uint32_t mu_type,
				 hsm_storage_status_t *storage_status)
{
	open_se_lib_serv_args_t se_lib_serv_args = {0};
	open_svc_key_store_args_t key_store_args = {0};
	struct se_lib_service_hdl_s *se_lib_serv_ptr;
	struct hsm_session_hdl_s *sess_ptr;
	hsm_err_t err = HSM_UNKNOWN_HANDLE;

	*storage_status = HSM_STORAGE_STATUS_FETCH_FAILED;
	if (!mu_type && !session_hdl)
		return HSM_INVALID_PARAM;

	if (session_hdl) {
		sess_ptr = session_hdl_to_ptr(session_hdl);
		if (!sess_ptr)
			/* consider session handle as se_lib_service_handle */
			se_lib_serv_ptr = se_lib_serv_hdl_to_ptr(session_hdl);
		else
			se_lib_serv_ptr =
				se_lib_serv_hdl_to_ptr(sess_ptr->se_lib_serv_hdl);
	} else {
		se_lib_serv_args.mu_type = mu_type;
		se_lib_open_service(&se_lib_serv_args, &se_lib_serv_args.se_lib_serv_hdl);
		se_lib_serv_ptr =
			se_lib_serv_hdl_to_ptr(se_lib_serv_args.se_lib_serv_hdl);
	}
	if (!se_lib_serv_ptr || !se_lib_serv_ptr->phdl)
		return err;

	key_store_args.flags = HSM_SVC_KEY_STORE_FLAGS_KEY_STORE_STATUS;

	err = exchange_key_store_open_msg(se_lib_serv_ptr->phdl, se_lib_serv_ptr->mu_type,
					  session_hdl, &key_store_args);

	if (err == HSM_NO_ERROR) {
		*storage_status =
			HSM_KEY_STORE_STATUS_STORAGE_OPEN(key_store_args.key_store_hdl) ?
			HSM_STORAGE_STATUS_OPENED : HSM_STORAGE_STATUS_NOT_OPENED;
	} else {
		se_err("%s RSP Error: SAB_KEY_STORE_OPEN_REQ [0x%x].\n",
		       "HSM GET KEY STORE STATUS", err);
	}

	if (!session_hdl)
		se_lib_close_service(se_lib_serv_args.se_lib_serv_hdl);

	return err;
}
#endif
