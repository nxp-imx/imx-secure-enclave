// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_get_key_attr.h"

#include "sab_process_msg.h"

#include "plat_utils.h"
#include "plat_os_abs.h"

hsm_err_t hsm_get_key_attr(hsm_hdl_t key_management_hdl,
			   op_get_key_attr_args_t *args)
{
	uint32_t error;
	struct hsm_service_hdl_s *serv_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	do {
		if ((args == NULL) || (args->key_identifier == 0))
			break;

		if (!key_management_hdl) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		serv_ptr = service_hdl_to_ptr(key_management_hdl);
		if (serv_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		error = process_sab_msg(serv_ptr->session->phdl,
					serv_ptr->session->mu_type,
					SAB_GET_KEY_ATTR_REQ,
					MT_SAB_GET_KEY_ATTR,
					(uint32_t)key_management_hdl,
					args, &rsp_code);

		err = sab_rating_to_hsm_err(error, serv_ptr->session->phdl);

		if (err != HSM_NO_ERROR) {
			se_err("HSM Error: SAB_GET_KEY_ATTR_REQ [0x%x].\n", err);
			break;
		}
		err = sab_rating_to_hsm_err(rsp_code, serv_ptr->session->phdl);

		if (err != HSM_NO_ERROR)
			se_err("HSM RSP Error: SAB_GET_KEY_ATTR_REQ [0x%x].\n", err);

	} while (false);

	return err;
}
