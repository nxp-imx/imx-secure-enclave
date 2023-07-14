// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <stdbool.h>
#include <stdio.h>

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_data_storage.h"

#include "sab_process_msg.h"

hsm_err_t hsm_open_data_storage_service(hsm_hdl_t key_store_hdl,
					open_svc_data_storage_args_t *args,
					hsm_hdl_t *data_storage_hdl)
{
	struct hsm_service_hdl_s *key_store_serv_ptr;
	struct hsm_service_hdl_s *data_storage_serv_ptr;
	uint32_t error;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;
	hsm_err_t err = HSM_GENERAL_ERROR;

	do {
		if ((args == NULL) || (data_storage_hdl == NULL)) {
			break;
		}

		if (!key_store_hdl) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		key_store_serv_ptr = service_hdl_to_ptr(key_store_hdl);
		if (key_store_serv_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		data_storage_serv_ptr = add_service(key_store_serv_ptr->session);
		if (data_storage_serv_ptr == NULL) {
			break;
		}

		error = process_sab_msg(key_store_serv_ptr->session->phdl,
					key_store_serv_ptr->session->mu_type,
					SAB_DATA_STORAGE_OPEN_REQ,
					MT_SAB_DATA_STORAGE,
					(uint32_t)key_store_hdl,
					args, &rsp_code);

		err = sab_rating_to_hsm_err(error);

		if (err != HSM_NO_ERROR) {
			se_err("HSM Error: SAB_DATA_STORAGE_OPEN_REQ [0x%x].\n", err);
			break;
		}

		err = sab_rating_to_hsm_err(rsp_code);
		if (err != HSM_NO_ERROR) {
			se_err("HSM Error: SAB_DATA_STORAGE_OPEN_REQ [0x%x].\n",
				err);
			delete_service(data_storage_serv_ptr);
			break;
		}

		data_storage_serv_ptr->service_hdl = args->data_storage_handle;
		*data_storage_hdl = data_storage_serv_ptr->service_hdl;
	} while (false);

	return err;
}

hsm_err_t hsm_close_data_storage_service(hsm_hdl_t data_storage_hdl)
{
	struct hsm_service_hdl_s *serv_ptr;
	uint32_t error;
	hsm_err_t err = HSM_UNKNOWN_HANDLE;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	do {
		if (!data_storage_hdl)
			break;

		serv_ptr = service_hdl_to_ptr(data_storage_hdl);

		if (!serv_ptr)
			break;

		error = process_sab_msg(serv_ptr->session->phdl,
					serv_ptr->session->mu_type,
					SAB_DATA_STORAGE_CLOSE_REQ,
					MT_SAB_DATA_STORAGE,
					(uint32_t)data_storage_hdl,
					NULL, &rsp_code);

		err = sab_rating_to_hsm_err(error);

		if (err != HSM_NO_ERROR) {
			se_err("HSM Error: SAB_DATA_STORAGE_CLOSE_REQ [0x%x].\n", err);
			break;
		}

		err = sab_rating_to_hsm_err(rsp_code);
		if (err != HSM_NO_ERROR) {
			se_err("HSM RSP Error: SAB_DATA_STORAGE_CLOSE_REQ [0x%x].\n",
				err);
		}

		/* Do not delete the service if SAB_ERR is 0x0429. */
		if (!((GET_RATING_CODE(rsp_code) == SAB_INVALID_PARAM_RATING) &&
		    (GET_STATUS_CODE(rsp_code) == SAB_FAILURE_STATUS))) {
			delete_service(serv_ptr);
		}
	} while (false);

	return err;
}

hsm_err_t hsm_data_storage(hsm_hdl_t data_storage_hdl,
				op_data_storage_args_t *args)
{
	uint32_t error;
	struct hsm_service_hdl_s *serv_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	do {
		if (args == NULL) {
			break;
		}

		if (!data_storage_hdl) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		serv_ptr = service_hdl_to_ptr(data_storage_hdl);
		if (serv_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		error = process_sab_msg(serv_ptr->session->phdl,
					serv_ptr->session->mu_type,
					SAB_DATA_STORAGE_REQ,
					MT_SAB_DATA_STORAGE,
					(uint32_t)data_storage_hdl,
					args, &rsp_code);

		err = sab_rating_to_hsm_err(error);

		if (err != HSM_NO_ERROR) {
			se_err("HSM Error: SAB_DATA_STORAGE_REQ [0x%x].\n", err);
			break;
		}

		err = sab_rating_to_hsm_err(rsp_code);
		if (err != HSM_NO_ERROR) {
			se_err("HSM RSP Error: SAB_DATA_STORAGE_REQ [0x%x].\n",
				err);
		}

	} while (false);

	return err;
}

hsm_err_t hsm_data_ops(hsm_hdl_t key_store_hdl,
			 op_data_storage_args_t *args)
{
	open_svc_data_storage_args_t open_data_args = {0};
	hsm_hdl_t data_storage_hdl = 0;
	hsm_err_t err;
	/* Stores the error status of the main operation.
	 */
	hsm_err_t op_err;

	open_data_args.flags = args->svc_flags;

	op_err = hsm_open_data_storage_service(key_store_hdl, &open_data_args,
					    &data_storage_hdl);
	if (op_err) {
		se_err("err: 0x%x hsm_open_data_storage_service hdl: 0x%08x\n",
				op_err, data_storage_hdl);
		goto exit;
	}

	op_err = hsm_data_storage(data_storage_hdl, args);
	if (op_err)
		se_err("Error: 0x%x %s hdl: 0x%08x\n", op_err, __func__,
			   data_storage_hdl);

	err = hsm_close_data_storage_service(data_storage_hdl);
	if (err) {
		se_err("err: 0x%x hsm_close_data_storage_service hdl: 0x%08x\n",
				err, data_storage_hdl);
		if (op_err == HSM_NO_ERROR)
			op_err = err;
	}

exit:
	return op_err;
}

#if MT_SAB_ENC_DATA_STORAGE
hsm_err_t hsm_enc_data_storage(hsm_hdl_t data_storage_hdl,
			       op_enc_data_storage_args_t *args)
{
	uint32_t error;
	struct hsm_service_hdl_s *serv_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	do {
		if (!args)
			break;

		if (!data_storage_hdl) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		serv_ptr = service_hdl_to_ptr(data_storage_hdl);
		if (!serv_ptr) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		error = process_sab_msg(serv_ptr->session->phdl,
					serv_ptr->session->mu_type,
					SAB_ENC_DATA_STORAGE_REQ,
					MT_SAB_ENC_DATA_STORAGE,
					(uint32_t)data_storage_hdl,
					args, &rsp_code);

		err = sab_rating_to_hsm_err(error);

		if (err != HSM_NO_ERROR) {
			se_err("HSM Error: SAB_ENC_DATA_STORAGE_REQ [0x%x].\n", err);
			break;
		}

		err = sab_rating_to_hsm_err(rsp_code);
		if (err != HSM_NO_ERROR) {
			se_err("HSM RSP Error: SAB_ENC_DATA_STORAGE_REQ [0x%x].\n",
			       err);
		}

	} while (false);

	return err;
}

hsm_err_t hsm_enc_data_ops(hsm_hdl_t key_store_hdl,
			   op_enc_data_storage_args_t *args)
{
	open_svc_data_storage_args_t open_data_args = {0};
	hsm_hdl_t data_storage_hdl = 0;
	hsm_err_t err;
	/* Stores the error status of the main operation.
	 */
	hsm_err_t op_err;

	open_data_args.flags = args->svc_flags;

	op_err = hsm_open_data_storage_service(key_store_hdl,
					       &open_data_args,
					       &data_storage_hdl);
	if (op_err) {
		se_err("err: 0x%x hsm_open_data_storage_service hdl: 0x%08x\n",
		       op_err, data_storage_hdl);
		goto exit;
	}

	op_err = hsm_enc_data_storage(data_storage_hdl, args);
	if (op_err)
		se_err("err: 0x%x hsm_enc_data_storage hdl: 0x%08x\n",
		       op_err, data_storage_hdl);

	err = hsm_close_data_storage_service(data_storage_hdl);
	if (err) {
		se_err("err: 0x%x hsm_close_data_storage_service hdl: 0x%08x\n",
		       err, data_storage_hdl);
		if (op_err == HSM_NO_ERROR)
			op_err = err;
	}
exit:
	return op_err;
}
#endif
