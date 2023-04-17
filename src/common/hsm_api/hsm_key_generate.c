// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "internal/hsm_key.h"
#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_key_generate.h"

#include "sab_process_msg.h"

#include "plat_utils.h"
#include "plat_os_abs.h"

hsm_err_t hsm_generate_key(hsm_hdl_t key_management_hdl,
			   op_generate_key_args_t *args)
{
	uint32_t error;
	struct hsm_service_hdl_s *serv_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	do {
		if ((args == NULL) || (args->key_identifier == NULL)) {
			break;
		}

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
					SAB_KEY_GENERATE_REQ,
					MT_SAB_KEY_GENERATE,
					(uint32_t)key_management_hdl,
					args, &rsp_code);

		err = sab_rating_to_hsm_err(error);

		if (err != HSM_NO_ERROR) {
			se_err("HSM Error: SAB_KEY_GENERATE_REQ [0x%x].\n", err);
			break;
		}

		err = sab_rating_to_hsm_err(rsp_code);
		if (err != HSM_NO_ERROR)
			se_err("HSM RSP Error: SAB_KEY_GENERATE_REQ [0x%x].\n",
				err);
	} while (false);

	return err;
}
