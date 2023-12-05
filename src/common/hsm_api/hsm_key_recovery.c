// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_key_recovery.h"

#include "sab_process_msg.h"

#include "plat_utils.h"
#include "plat_os_abs.h"

hsm_err_t hsm_pub_key_recovery(hsm_hdl_t key_store_hdl,
			       op_pub_key_recovery_args_t *args)
{
	uint32_t error;
	struct hsm_service_hdl_s *key_store_serv_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	do {
		if (!args)
			break;

		if (!key_store_hdl) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		key_store_serv_ptr = service_hdl_to_ptr(key_store_hdl);
		if (key_store_serv_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		error = process_sab_msg(key_store_serv_ptr->session->phdl,
					key_store_serv_ptr->session->mu_type,
					SAB_PUB_KEY_RECOVERY_REQ,
					MT_SAB_KEY_RECOVERY,
					(uint32_t)key_store_hdl,
					args, &rsp_code);

		err = sab_rating_to_hsm_err(error, key_store_serv_ptr->session->phdl);

		if (err != HSM_NO_ERROR) {
			se_err("HSM Error: SAB_PUB_KEY_RECOVERY_REQ [0x%x].\n", err);
			break;
		}

		err = sab_rating_to_hsm_err(rsp_code, key_store_serv_ptr->session->phdl);
		if (err  != HSM_NO_ERROR)
			se_err("HSM RSP Error: SAB_PUB_KEY_RECOVERY_REQ [0x%x].\n", err);

	} while (false);

	return err;
}

