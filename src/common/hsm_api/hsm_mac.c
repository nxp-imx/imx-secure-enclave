// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_mac.h"

#include "sab_process_msg.h"

#include "plat_utils.h"
#include "plat_os_abs.h"

hsm_err_t hsm_mac_one_go(hsm_hdl_t mac_hdl,
			 op_mac_one_go_args_t *args,
			 hsm_mac_verification_status_t *status)
{
	uint32_t error;
	struct hsm_service_hdl_s *serv_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	do {
		if (!args || !status)
			break;

		if (!mac_hdl) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		serv_ptr = service_hdl_to_ptr(mac_hdl);
		if (serv_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		error = process_sab_msg(serv_ptr->session->phdl,
					serv_ptr->session->mu_type,
					SAB_MAC_ONE_GO_REQ,
					MT_SAB_MAC,
					(uint32_t)mac_hdl,
					args, &rsp_code);

		err = sab_rating_to_hsm_err(error);

		if (err != HSM_NO_ERROR) {
			se_err("HSM Error: SAB_MAC_ONE_GO_REQ [0x%x].\n", err);
			break;
		}

		*status = args->verification_status;

		err = sab_rating_to_hsm_err(rsp_code);

		if (err != HSM_NO_ERROR) {
			se_err("HSM RSP Error: SAB_MAC_ONE_GO_REQ [0x%x].\n", err);
			break;
		}


		if ((args->flags == HSM_OP_MAC_ONE_GO_FLAGS_MAC_VERIFICATION) &&
			(args->verification_status != HSM_MAC_VERIFICATION_STATUS_SUCCESS)) {
			err = HSM_SIGNATURE_INVALID;
			se_err("\nHSM Error: HSM_SIGNATURE_INVALID (0x%x)\n",
			       HSM_SIGNATURE_INVALID);
		}

	} while (false);

	return err;
}

hsm_err_t hsm_open_mac_service(hsm_hdl_t key_store_hdl,
			       open_svc_mac_args_t *args,
			       hsm_hdl_t *mac_hdl)
{
	uint32_t error;
	struct hsm_service_hdl_s *key_store_serv_ptr;
	struct hsm_service_hdl_s *mac_serv_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	do {
		if ((args == NULL) || (mac_hdl == NULL)) {
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

		mac_serv_ptr = add_service(key_store_serv_ptr->session);
		if (mac_serv_ptr == NULL) {
			break;
		}

		error = process_sab_msg(key_store_serv_ptr->session->phdl,
					key_store_serv_ptr->session->mu_type,
					SAB_MAC_OPEN_REQ,
					MT_SAB_MAC,
					(uint32_t)key_store_hdl,
					args, &rsp_code);

		err = sab_rating_to_hsm_err(error);

		if (err != HSM_NO_ERROR) {
			se_err("HSM Error: SAB_MAC_OPEN_REQ [0x%x].\n", err);
			delete_service(mac_serv_ptr);
			break;
		}

		err = sab_rating_to_hsm_err(rsp_code);

		if (err != HSM_NO_ERROR) {
			se_err("HSM RSP Error: SAB_MAC_OPEN_REQ [0x%x].\n", err);
			delete_service(mac_serv_ptr);
			break;
		}
		mac_serv_ptr->service_hdl = args->mac_serv_hdl;
		*mac_hdl = mac_serv_ptr->service_hdl;
	} while (false);

	return err;
}

hsm_err_t hsm_close_mac_service(hsm_hdl_t mac_hdl)
{
	struct hsm_service_hdl_s *serv_ptr;
	uint32_t error;
	hsm_err_t err = HSM_UNKNOWN_HANDLE;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	do {
		if (!mac_hdl)
			break;

		serv_ptr = service_hdl_to_ptr(mac_hdl);

		if (!serv_ptr)
			break;

		error = process_sab_msg(serv_ptr->session->phdl,
					serv_ptr->session->mu_type,
					SAB_MAC_CLOSE_REQ,
					MT_SAB_MAC,
					mac_hdl,
					NULL, &rsp_code);

		err = sab_rating_to_hsm_err(error);

		if (err != HSM_NO_ERROR) {
			se_err("HSM Error: SAB_MAC_CLOSE_REQ [0x%x].\n", err);
			delete_service(serv_ptr);
			break;
		}

		err = sab_rating_to_hsm_err(rsp_code);

		if (err != HSM_NO_ERROR) {
			se_err("HSM RSP Error: SAB_MAC_CLOSE_REQ [0x%x].\n", err);
		}
		delete_service(serv_ptr);
	} while (false);

	return err;
}

hsm_err_t hsm_do_mac(hsm_hdl_t key_store_hdl, op_mac_one_go_args_t *mac_one_go)
{
	hsm_err_t err;
	/* Stores the error status of the main operation.
	 */
	hsm_err_t op_err;
	hsm_hdl_t sg0_mac_hdl = 0;
	open_svc_mac_args_t mac_srv_args = {0};
#ifndef PSA_COMPLIANT
	mac_srv_args.flags = mac_one_go->svc_flags;
#endif

	op_err = hsm_open_mac_service(key_store_hdl, &mac_srv_args, &sg0_mac_hdl);
	if (op_err) {
		se_err("err: 0x%x hsm_open_mac_service err: hdl: 0x%08x\n",
				op_err, sg0_mac_hdl);
		goto exit;
	}

	op_err = hsm_mac_one_go(sg0_mac_hdl, mac_one_go, &mac_one_go->verification_status);
	if (op_err) {
		se_err("\n\terr: 0x%x hsm_mac_one_go GEN hdl: 0x%08x\n",
				op_err, sg0_mac_hdl);
	}

	err = hsm_close_mac_service(sg0_mac_hdl);
	if (err) {
		se_err("0x%x hsm_close_mac_service hdl: 0x%x\n", err, sg0_mac_hdl);
		if (op_err == HSM_NO_ERROR)
			op_err = err;
	}

exit:
	return op_err;
}
