// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022, 2023 NXP
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_managekey.h"

#include "sab_process_msg.h"

#include "plat_utils.h"
#include "plat_os_abs.h"

hsm_err_t hsm_manage_key(hsm_hdl_t key_management_hdl,
			 op_manage_key_args_t *args)
{
	int32_t error = 1;
	struct hsm_service_hdl_s *serv_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t rsp_code;

	do {
		if ((args == NULL) || (args->key_identifier == NULL)) {
			break;
		}
		serv_ptr = service_hdl_to_ptr(key_management_hdl);
		if (serv_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		error = process_sab_msg(serv_ptr->session->phdl,
					serv_ptr->session->mu_type,
					SAB_MANAGE_KEY_REQ,
					MT_SAB_MANAGE_KEY,
					(uint32_t)key_management_hdl,
					args, &rsp_code);

		err = sab_rating_to_hsm_err(error, serv_ptr->session->phdl);

		if (err != HSM_NO_ERROR) {
			se_err("HSM Error: SAB_MANAGE_KEY_REQ [0x%x].\n", err);
			break;
		}
		err = sab_rating_to_hsm_err(rsp_code, serv_ptr->session->phdl);

		if (err != HSM_NO_ERROR) {
			se_err("HSM RSP Error: SAB_MANAGE_KEY_REQ [0x%x].\n", err);
		}

	} while (false);

	return err;
}

hsm_err_t hsm_manage_key_ext(hsm_hdl_t key_management_hdl,
				op_manage_key_ext_args_t *args)
{
	int32_t error = 1;
	struct hsm_service_hdl_s *serv_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t rsp_code;

	do {
		if ((args == NULL) || (args->key_identifier == NULL)) {
			break;
		}
		serv_ptr = service_hdl_to_ptr(key_management_hdl);
		if (serv_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		error = process_sab_msg(serv_ptr->session->phdl,
					serv_ptr->session->mu_type,
					SAB_MANAGE_KEY_EXT_REQ,
					MT_SAB_MANAGE_KEY,
					(uint32_t)key_management_hdl,
					args, &rsp_code);

		err = sab_rating_to_hsm_err(error, serv_ptr->session->phdl);

		if (err != HSM_NO_ERROR) {
			se_err("HSM Error: SAB_MANAGE_KEY_EXT_REQ [0x%x].\n", err);
		}

		err = sab_rating_to_hsm_err(rsp_code, serv_ptr->session->phdl);

		if (err != HSM_NO_ERROR) {
			se_err("HSM RSP Error: SAB_MANAGE_KEY_EXT_REQ [0x%x].\n", err);
		}

	} while (false);

	return err;
}
