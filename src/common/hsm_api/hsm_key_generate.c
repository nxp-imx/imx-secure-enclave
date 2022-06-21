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

		error = set_key_type_n_sz(args->key_type,
					&args->bit_key_sz,
					&args->psa_key_type,
					&args->out_size);

		if (error == HSM_KEY_OP_FAIL) {
			printf("HSM Error: Invalid Key Type is given [0x%x].\n",
				args->key_type);
			break;
		}

		error = process_sab_msg(serv_ptr->session->phdl,
					serv_ptr->session->mu_type,
					SAB_KEY_GENERATE_REQ,
					MT_SAB_KEY_GENERATE,
					(uint32_t)key_management_hdl,
					args, &rsp_code);

		if (error) {
			printf("SAB Engine Error[0x%x]: SAB_KEY_GEN_REQ.\n",
								error);
			break;
		}

		if (rsp_code) {
			printf("SAB FW Err[0x%x]: SAB_KEY_GEN_REQ.\n",
								rsp_code);
		}

		err = sab_rating_to_hsm_err(rsp_code);
		if (err  != HSM_NO_ERROR) {
			printf("HSM Error: HSM_KEY_GENERATE_REQ [0x%x].\n", err);
		}

	} while (false);

	return err;
}
