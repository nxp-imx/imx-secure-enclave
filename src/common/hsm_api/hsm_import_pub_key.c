// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <stdio.h>

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_import_pub_key.h"

#include "sab_process_msg.h"

hsm_err_t hsm_import_public_key(hsm_hdl_t signature_ver_hdl,
				op_import_public_key_args_t *args)
{
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;
	uint32_t lib_err;
	struct hsm_service_hdl_s *serv_ptr;

	do {
		if (!args || !args->key_ref)
			break;

		serv_ptr = service_hdl_to_ptr(signature_ver_hdl);
		if (!serv_ptr) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		lib_err = process_sab_msg(serv_ptr->session->phdl,
					  serv_ptr->session->mu_type,
					  SAB_IMPORT_PUB_KEY,
					  MT_SAB_IMPORT_PUB_KEY,
					  (uint32_t)signature_ver_hdl,
					  args,
					  &rsp_code);

		err =  lib_err_to_hsm_err(lib_err);
		if (err != HSM_NO_ERROR)
			break;

		err = sab_rating_to_hsm_err(rsp_code);
		if (err != HSM_NO_ERROR) {
			se_err("HSM RSP Error: SAB_IMPORT_PUB_KEY [0x%x].\n", err);
			break;
		}

	} while (false);

	return err;
}
