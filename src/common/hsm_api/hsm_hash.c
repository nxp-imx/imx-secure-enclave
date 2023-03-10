/*
 * Copyright 2022-2023 NXP
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
#include "internal/hsm_hash.h"

#include "sab_process_msg.h"

#include "plat_utils.h"
#include "plat_os_abs.h"

hsm_err_t hsm_hash_one_go(hsm_hdl_t hash_hdl,
			  op_hash_one_go_args_t *args)
{
	int32_t error = 1;
#ifndef PSA_COMPLIANT
	struct hsm_service_hdl_s *serv_ptr;
#else
	struct hsm_session_hdl_s *sess_ptr;
#endif
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t rsp_code;

	do {
		if (args == NULL) {
			break;
		}

#ifndef PSA_COMPLIANT
		serv_ptr = service_hdl_to_ptr(hash_hdl);
		if (serv_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}
		sess_ptr = serv_ptr->session;
#else
		/* For PSA compliant HASH API
		 * use session handle.
		 */
		sess_ptr = session_hdl_to_ptr(hash_hdl);
		if (!sess_ptr) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}
#endif
		error = process_sab_msg(sess_ptr->phdl,
					sess_ptr->mu_type,
					SAB_HASH_ONE_GO_REQ,
					MT_SAB_HASH_GEN,
					(uint32_t)hash_hdl,
					args, &rsp_code);

		err = sab_rating_to_hsm_err(error);

		if (err != HSM_NO_ERROR) {
			se_err("HSM Error: SAB_HASH_ONE_GO_REQ [0x%x].\n", err);
			break;
		}
		err = sab_rating_to_hsm_err(rsp_code);
		if (err != HSM_NO_ERROR)
			se_err("HSM RSP Error: SAB_HASH_ONE_GO_REQ [0x%x].\n",
				err);

	} while (false);

	return err;
}

#ifndef PSA_COMPLIANT
hsm_err_t hsm_open_hash_service(hsm_hdl_t session_hdl,
				open_svc_hash_args_t *args,
				hsm_hdl_t *hash_hdl)
{
	struct hsm_session_hdl_s *sess_ptr;
	struct hsm_service_hdl_s *serv_ptr;
	int32_t error = 1;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t rsp_code;

	do {
		if ((args == NULL) || (hash_hdl == NULL)) {
			break;
		}
		sess_ptr = session_hdl_to_ptr(session_hdl);
		if (sess_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		serv_ptr = add_service(sess_ptr);
		if (serv_ptr == NULL) {
			break;
		}

		error = process_sab_msg(serv_ptr->session->phdl,
					serv_ptr->session->mu_type,
					SAB_HASH_OPEN_REQ,
					MT_SAB_HASH_GEN,
					session_hdl,
					args, &rsp_code);

		err = sab_rating_to_hsm_err(error);

		if (err != HSM_NO_ERROR) {
			se_err("HSM Error: SAB_HASH_OPEN_REQ [0x%x].\n", err);
			delete_service(serv_ptr);
			break;
		}

		err = sab_rating_to_hsm_err(rsp_code);
		if (err != HSM_NO_ERROR) {
			se_err("HSM RSP Error: SAB_HASH_OPEN_REQ [0x%x].\n",
				err);
			delete_service(serv_ptr);
			break;
		}

		serv_ptr->service_hdl = args->hash_hdl;
		*hash_hdl = args->hash_hdl;
	} while (false);

	return err;
}

hsm_err_t hsm_close_hash_service(hsm_hdl_t hash_hdl)
{
	struct hsm_service_hdl_s *serv_ptr;
	int32_t error = 1;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t rsp_code;
	open_svc_hash_args_t args;

	do {
		serv_ptr = service_hdl_to_ptr(hash_hdl);
		if (serv_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		error = process_sab_msg(serv_ptr->session->phdl,
					serv_ptr->session->mu_type,
					SAB_HASH_CLOSE_REQ,
					MT_SAB_HASH_GEN,
					(uint32_t)hash_hdl,
					&args, &rsp_code);

		err = sab_rating_to_hsm_err(error);

		if (err != HSM_NO_ERROR)
			se_err("HSM Error: SAB_HASH_CLOSE_REQ [0x%x].\n", err);

		err = sab_rating_to_hsm_err(rsp_code);
		if (err != HSM_NO_ERROR)
			se_err("HSM RSP Error: SAB_HASH_CLOSE_REQ [0x%x].\n",
				err);

		delete_service(serv_ptr);
	} while (false);

	return err;
}
#endif

hsm_err_t hsm_do_hash(hsm_hdl_t hash_sess, op_hash_one_go_args_t *hash_args)
{
#ifndef PSA_COMPLIANT
	hsm_err_t err = HSM_GENERAL_ERROR;
#endif
	/* Stores the error status of the main operation.
	 */
	hsm_err_t op_err = HSM_NO_ERROR;
#ifndef PSA_COMPLIANT
	hsm_hdl_t hash_serv;
	open_svc_hash_args_t hash_serv_args = {0};

	op_err = hsm_open_hash_service(hash_sess, &hash_serv_args, &hash_serv);
	if (op_err) {
		se_err("err: 0x%x hsm_open_hash_service.\n", op_err);
		goto exit;
	}

	op_err = hsm_hash_one_go(hash_serv, hash_args);
#else
	op_err = hsm_hash_one_go(hash_sess, hash_args);
#endif
	if (op_err)
		se_err("err: 0x%x HASH failed hash size: 0x%08x\n", op_err, hash_args.output_size);

#ifndef PSA_COMPLIANT
	err = hsm_close_hash_service(hash_serv);
	if (err) {
		se_err("err: 0x%x hsm_close_hash_service hdl: 0x%08x\n", err, hash_serv);
		if (op_err == HSM_NO_ERROR)
			op_err = err;
	}
exit:
#endif
	return op_err;
}
