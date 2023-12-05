// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <stdio.h>

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_key_management.h"

#include "sab_process_msg.h"

hsm_err_t hsm_open_key_management_service(hsm_hdl_t key_store_hdl,
					  open_svc_key_management_args_t *args,
					  hsm_hdl_t *key_management_hdl)
{
	struct hsm_service_hdl_s *key_store_serv_ptr;
	struct hsm_service_hdl_s *key_mgmt_serv_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;
	uint32_t error;

	do {
		if (!args || !key_management_hdl)
			break;

		if (!key_store_hdl) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		key_store_serv_ptr = service_hdl_to_ptr(key_store_hdl);
		if (!key_store_serv_ptr) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		key_mgmt_serv_ptr = add_service(key_store_serv_ptr->session);
		if (!key_mgmt_serv_ptr)
			break;

		error = process_sab_msg(key_store_serv_ptr->session->phdl,
					key_store_serv_ptr->session->mu_type,
					SAB_KEY_MANAGEMENT_OPEN_REQ,
					MT_SAB_KEY_MANAGEMENT,
					key_store_hdl,
					args,
					&rsp_code);

		err = sab_rating_to_hsm_err(error, key_store_serv_ptr->session->phdl);

		if (err != HSM_NO_ERROR) {
			se_err("HSM Error: SAB_KEY_MANAGEMENT_OPEN_REQ [0x%x].\n",
			       err);
			delete_service(key_mgmt_serv_ptr);
			break;
		}

		err = sab_rating_to_hsm_err(rsp_code, key_store_serv_ptr->session->phdl);

		if (err != HSM_NO_ERROR) {
			se_err("HSM RSP Error: SAB_KEY_MANAGEMENT_OPEN_REQ [0x%x].\n",
			       err);
			delete_service(key_mgmt_serv_ptr);
			break;
		}

		key_mgmt_serv_ptr->service_hdl = args->key_management_hdl;
		*key_management_hdl = key_mgmt_serv_ptr->service_hdl;
	} while (false);

	return err;
}

hsm_err_t hsm_close_key_management_service(hsm_hdl_t key_management_hdl)
{
	struct hsm_service_hdl_s *serv_ptr;
	hsm_err_t err = HSM_UNKNOWN_HANDLE;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;
	uint32_t error;

	do {
		if (!key_management_hdl)
			break;

		serv_ptr = service_hdl_to_ptr(key_management_hdl);

		if (!serv_ptr)
			break;

		error = process_sab_msg(serv_ptr->session->phdl,
					serv_ptr->session->mu_type,
					SAB_KEY_MANAGEMENT_CLOSE_REQ,
					MT_SAB_KEY_MANAGEMENT,
					key_management_hdl,
					NULL,
					&rsp_code);

		err = sab_rating_to_hsm_err(error, serv_ptr->session->phdl);

		if (err != HSM_NO_ERROR) {
			se_err("HSM Error: SAB_KEY_MANAGEMENT_CLOSE_REQ [0x%x].\n",
			       err);
			delete_service(serv_ptr);
			break;
		}

		err = sab_rating_to_hsm_err(rsp_code, serv_ptr->session->phdl);

		if (err != HSM_NO_ERROR)
			se_err("HSM RSP Error: SAB_KEY_MANAGEMENT_CLOSE_REQ [0x%x].\n",
			       err);
		/*
		 *  Do not delete the service if SAB_ERR is 0x0429.
		 *  i.e. in case of HSM_INVALID_PARAM (0x04)
		 */
		if (err != HSM_INVALID_PARAM)
			delete_service(serv_ptr);

	} while (false);

	return err;
}

