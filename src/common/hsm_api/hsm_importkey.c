/*
 * Copyright 2022 NXP
 *
 * NXP Confidential.
 * This software is owned or controlled by NXP and may only be used strictly
 * in accordance with the applicable license terms.  By expressly accepting
 * such terms or by downloading, installing, activating and/or otherwise using
 * the software, you are agreeing that you have read, and that you agree to
 * comply with and are bound by, such license terms.  If you do not agree to be
 * bound by the applicable license terms, then you may not retain, install,
 * activate or otherwise use the software.
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_importkey.h"

#include "sab_process_msg.h"

#include "plat_utils.h"
#include "plat_os_abs.h"

hsm_err_t hsm_import_key(hsm_hdl_t key_management_hdl,
			 op_import_key_args_t *args)
{
	int32_t error = 1;
	struct hsm_service_hdl_s *serv_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint16_t unused_out_sz;
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

		error = set_key_type_n_sz(args->key_type,
					&args->bit_key_sz,
					&args->psa_key_type,
					&unused_out_sz);

		if (error) {
			printf("HSM Error: Invalid Key Type is given [0x%x].\n",
				args->key_type);
			break;
		}

		if ((((args->flags & HSM_OP_IMPORT_KEY_FLAGS_PART_UNIQUE_ROOT_KEK)
			== HSM_OP_IMPORT_KEY_FLAGS_PART_UNIQUE_ROOT_KEK)
			|| ((args->flags & HSM_OP_IMPORT_KEY_FLAGS_COMMON_ROOT_KEK)
			== HSM_OP_IMPORT_KEY_FLAGS_COMMON_ROOT_KEK))
			&& (args->key_lifetime == 0)
			&& (args->key_usage == 0)
			&& (args->psa_key_type == 0)
			&& (args->bit_key_sz == 0)
			&& (args->permitted_algo == 0))
			break;

		error = process_sab_msg(serv_ptr->session->phdl,
					serv_ptr->session->mu_type,
					SAB_IMPORT_KEY_REQ,
					MT_SAB_IMPORT_KEY,
					(uint32_t)key_management_hdl,
					args, &rsp_code);

		err = sab_rating_to_hsm_err(rsp_code);

		if (!error && err != HSM_NO_ERROR) {
			printf("HSM Error: HSM_IMPORT_KEY_REQ [0x%x].\n", err);
		}

	} while (false);

	return err;
}
