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
#include "internal/hsm_hash.h"

#include "sab_process_msg.h"

#include "plat_utils.h"
#include "plat_os_abs.h"

hsm_err_t hsm_hash_one_go(hsm_hdl_t hash_hdl,
			  op_hash_one_go_args_t *args)
{
	int32_t error = 1;
	struct hsm_service_hdl_s *serv_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t rsp_code;

	do {
		if (args == NULL) {
			break;
		}

		serv_ptr = service_hdl_to_ptr(hash_hdl);
		if (serv_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		error = process_sab_msg(serv_ptr->session->phdl,
					serv_ptr->session->mu_type,
					SAB_HASH_ONE_GO_REQ,
					MT_SAB_HASH_GEN,
					(uint32_t)hash_hdl,
					args, &rsp_code);

		err = sab_rating_to_hsm_err(rsp_code);

		if (!error && err != HSM_NO_ERROR) {
			printf("HSM Error: HSM_HASH_ONE_GO_REQ [0x%x].\n", err);
		}

	} while (false);

	return err;
}

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

		err = sab_rating_to_hsm_err(rsp_code);

		if (!error && err != HSM_NO_ERROR) {
			printf("HSM Error: HSM_HASH_ONE_GO_REQ [0x%x].\n", err);
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

		if (error == 0) {
			err = sab_rating_to_hsm_err(rsp_code);
		}
		delete_service(serv_ptr);
	} while (false);

	return err;
}

hsm_err_t hsm_do_hash(hsm_hdl_t hash_sess, op_hash_one_go_args_t *hash_args)
{
	hsm_err_t err;
	hsm_hdl_t hash_serv;
	open_svc_hash_args_t hash_serv_args;

	hash_serv_args.flags = hash_args->svc_flags;

	printf("\n---------------------------------------------------\n");
	printf("Secondary API: DO HASH test Start\n");
	printf("---------------------------------------------------\n");
	err = hsm_open_hash_service(hash_sess, &hash_serv_args, &hash_serv);


	err = hsm_hash_one_go(hash_serv, hash_args);
	if (err)
		printf("err: 0x%x hsm_hash_one_go hdl: 0x%08x\n", err, hash_serv);


	err = hsm_close_hash_service(hash_serv);
	if (err)
		printf("err: 0x%x hsm_close_hash_service hdl: 0x%08x\n", err, hash_serv);

	printf("\n---------------------------------------------------\n");
	printf("Secondary API: DO HASH test Complete\n");
	printf("---------------------------------------------------\n");

	return err;
}
