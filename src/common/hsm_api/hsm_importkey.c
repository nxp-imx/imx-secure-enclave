// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "internal/hsm_importkey.h"

#include "sab_process_msg.h"

#include "plat_utils.h"
#include "plat_os_abs.h"

hsm_err_t hsm_import_key(hsm_hdl_t key_management_hdl,
			 op_import_key_args_t *args)
{
	uint32_t error;
	struct hsm_service_hdl_s *serv_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	do {
		if (args == NULL) {
			break;
		}

		if ((args->input_lsb_addr == NULL) || (args->input_size == 0))
			break;

		if ((args->flags & HSM_OP_IMPORT_KEY_INPUT_E2GO_TLV)
			== HSM_OP_IMPORT_KEY_INPUT_SIGNED_MSG) {
			if ((args->key_blob == NULL)
					|| (args->key_blob_sz == 0)
					|| (args->iv == NULL)
					|| (args->iv_sz == 0))
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
					SAB_IMPORT_KEY_REQ,
					MT_SAB_IMPORT_KEY,
					(uint32_t)key_management_hdl,
					args, &rsp_code);

		err = sab_rating_to_hsm_err(error);

		if (err != HSM_NO_ERROR) {
			se_err("HSM Error: SAB_IMPORT_KEY_REQ [0x%x].\n", err);
			break;
		}

		err = sab_rating_to_hsm_err(rsp_code);

		if (err != HSM_NO_ERROR)
			se_err("HSM RSP Error: SAB_IMPORT_KEY_REQ [0x%x].\n", err);

	} while (false);

	return err;
}
