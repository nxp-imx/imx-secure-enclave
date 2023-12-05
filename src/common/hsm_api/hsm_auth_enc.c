// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_auth_enc.h"
#include "internal/hsm_cipher.h"

#include "sab_process_msg.h"

#include "plat_utils.h"
#include "plat_os_abs.h"

hsm_err_t hsm_auth_enc(hsm_hdl_t cipher_hdl, op_auth_enc_args_t *args)
{
	hsm_err_t err = HSM_GENERAL_ERROR;
	struct hsm_service_hdl_s *serv_ptr;
	uint32_t error;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	do {
		if (args == NULL)
			break;

		if (!cipher_hdl) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		serv_ptr = service_hdl_to_ptr(cipher_hdl);
		if (serv_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		error = process_sab_msg(serv_ptr->session->phdl,
					serv_ptr->session->mu_type,
					SAB_AUTH_ENC_REQ,
					MT_SAB_AUTH_ENC,
					(uint32_t)cipher_hdl,
					args, &rsp_code);

		err = sab_rating_to_hsm_err(error, serv_ptr->session->phdl);
		if (err != HSM_NO_ERROR) {
			se_err("HSM Error: SAB_AUTH_ENC_REQ [0x%x].\n", err);
			break;
		}

		err = sab_rating_to_hsm_err(rsp_code, serv_ptr->session->phdl);
		if (err != HSM_NO_ERROR)
			se_err("HSM RSP Error: SAB_AUTH_ENC_REQ [0x%x].\n", err);

	} while (false);

	return err;
}

hsm_err_t hsm_do_auth_enc(hsm_hdl_t key_store_hdl,
			  op_auth_enc_args_t *auth_enc_args)
{
	hsm_hdl_t cipher_hdl = 0;
	hsm_err_t hsmret;
	/*
	 * Stores the error status of the main operation.
	 */
	hsm_err_t op_err;
	open_svc_cipher_args_t open_cipher_args = {0};

	op_err = hsm_open_cipher_service(key_store_hdl,
					 &open_cipher_args,
					 &cipher_hdl);
	if (op_err) {
		se_err("hsm_open_cipher_service ret: 0x%x\n", op_err);
		goto exit;
	}

	op_err = hsm_auth_enc(cipher_hdl, auth_enc_args);
	if (op_err)
		se_err("%s ret: 0x%x\n", __func__, op_err);

	hsmret = hsm_close_cipher_service(cipher_hdl);
	if (hsmret) {
		se_err("hsm_close_cipher_service ret: 0x%x\n", hsmret);
		if (op_err == HSM_NO_ERROR)
			op_err = hsmret;
	}

exit:
	return op_err;
}
