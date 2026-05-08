// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <stdio.h>

#include "internal/hsm_key_derivation.h"

#include "sab_process_msg.h"
#include "se_lib_serv_intern.h"

hsm_err_t hsm_key_derivation(hsm_hdl_t key_management_hdl,
			     op_key_derivation_args_t *args)
{
	uint32_t lib_err;
	struct se_lib_service_hdl_s *se_lib_serv_ptr;
	struct hsm_service_hdl_s *serv_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;
	struct plat_os_abs_hdl *phdl;
	uint32_t mu_type;

	do {
		if (!args)
			break;

		if (!key_management_hdl &&
		    !(args->flags & HSM_OP_KEY_DERIVATION_FLAGS_PLAINTEXT)) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		serv_ptr = service_hdl_to_ptr(key_management_hdl);
		if (!serv_ptr) {
			err = HSM_UNKNOWN_HANDLE;

			if (!(args->flags & HSM_OP_KEY_DERIVATION_FLAGS_PLAINTEXT))
				break;

			se_lib_serv_ptr = se_lib_serv_hdl_to_ptr(key_management_hdl);
			if (!se_lib_serv_ptr || !se_lib_serv_ptr->phdl)
				break;

			phdl = se_lib_serv_ptr->phdl;
			mu_type = se_lib_serv_ptr->mu_type;
			/* For HSM_OP_KEY_DERIVATION_FLAGS_PLAINTEXT, key_management_hdl
			 *  must be zero.
			 */
			key_management_hdl = 0;
		} else {
			phdl = serv_ptr->session->phdl;
			mu_type = serv_ptr->session->mu_type;
		}

		lib_err = process_sab_msg(phdl,
					  mu_type,
					  SAB_KEY_DERIVATION_REQ,
					  MT_SAB_KEY_DERIVATION,
					  key_management_hdl,
					  args, &rsp_code);

		err = lib_err_to_hsm_err(lib_err);
		if (err != HSM_NO_ERROR)
			break;

		err = sab_rating_to_hsm_err(rsp_code, phdl);
		if (err != HSM_NO_ERROR)
			se_err("HSM RSP Error: SAB_KEY_DERIVATION_REQ [0x%x].\n", err);

	} while (false);

	return err;
}
