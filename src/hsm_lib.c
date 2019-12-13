/*
 * Copyright 2019 NXP
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

#include "hsm_api.h"
#include "seco_os_abs.h"
#include "seco_sab_msg_def.h"
#include "seco_sab_messaging.h"
#include "seco_utils.h"

struct hsm_session_hdl_s {
	struct seco_os_abs_hdl *phdl;
	uint32_t session_hdl;
};

struct hsm_service_hdl_s {
	struct hsm_session_hdl_s *session;
	uint32_t service_hdl;
};

#define HSM_MAX_SESSIONS	(8u)
#define HSM_MAX_SERVICES	(32u)

static struct hsm_session_hdl_s hsm_sessions[HSM_MAX_SESSIONS] = {};
static struct hsm_service_hdl_s hsm_services[HSM_MAX_SERVICES] = {};

static struct hsm_session_hdl_s *session_hdl_to_ptr(uint32_t hdl)
{
	uint32_t i;
	struct hsm_session_hdl_s *ret;

	ret = NULL;
	for (i=0u; i<HSM_MAX_SESSIONS; i++) {
		if (hdl == hsm_sessions[i].session_hdl) {
			if (hsm_sessions[i].phdl != NULL) {
				ret = &hsm_sessions[i];
			}
			break;
		}
	}
	return ret;
}

static struct hsm_service_hdl_s *service_hdl_to_ptr(uint32_t hdl)
{
	uint32_t i;
	struct hsm_service_hdl_s *ret;

	ret = NULL;
	for (i=0u; i<HSM_MAX_SERVICES; i++) {
		if (hdl == hsm_services[i].service_hdl) {
			if (hsm_services[i].session != NULL) {
				ret = &hsm_services[i];
				break;
			}
		}
	}
	return ret;
}

static struct hsm_session_hdl_s *add_session(void)
{
	uint32_t i;
	struct hsm_session_hdl_s *s_ptr = NULL;

	for (i=0u; i<HSM_MAX_SESSIONS; i++) {
		if ((hsm_sessions[i].phdl == NULL)
			&& (hsm_sessions[i].session_hdl == 0u)) {
			/* Found an empty slot. */
			s_ptr = &hsm_sessions[i];
			break;
		}
	}
	return s_ptr;
}

static struct hsm_service_hdl_s *add_service(struct hsm_session_hdl_s *session)
{
	uint32_t i;
	struct hsm_service_hdl_s *s_ptr = NULL;

	for (i=0u; i<HSM_MAX_SERVICES; i++) {
		if ((hsm_services[i].session == NULL)
			&& (hsm_services[i].service_hdl == 0u)) {
			/* Found an empty slot. */
			s_ptr = &hsm_services[i];
			s_ptr->session = session;
			break;
		}
	}
	return s_ptr;
}

static void delete_session(struct hsm_session_hdl_s *s_ptr)
{
	if (s_ptr != NULL) {
		s_ptr->phdl = NULL;
		s_ptr->session_hdl = 0u;
	}
}

static void delete_service(struct hsm_service_hdl_s *s_ptr)
{
	if (s_ptr != NULL) {
		s_ptr->session = NULL;
		s_ptr->service_hdl = 0u;
	}
}

static hsm_err_t sab_rating_to_hsm_err(uint32_t sab_err)
{
	hsm_err_t hsm_err;

	if (GET_STATUS_CODE(sab_err) == SAB_SUCCESS_STATUS) {
		hsm_err = HSM_NO_ERROR;
	} else {
		hsm_err = (hsm_err_t)GET_RATING_CODE(sab_err);
		if (hsm_err == HSM_NO_ERROR) {
			hsm_err = HSM_GENERAL_ERROR;
		} 
	}

	return hsm_err;
}

hsm_err_t hsm_close_session(hsm_hdl_t session_hdl)
{
	struct hsm_session_hdl_s *s_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t sab_err;

	do {
		s_ptr = session_hdl_to_ptr(session_hdl);
		if (s_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		sab_err = sab_close_session_command(s_ptr->phdl,
						session_hdl);
		err = sab_rating_to_hsm_err(sab_err);

		seco_os_abs_close_session(s_ptr->phdl);

		delete_session(s_ptr);

		// TODO: should we close all associated services here ?
		// or sanity check that all services have been closed ?
	} while (false);

	return err;
}

hsm_err_t hsm_open_session(open_session_args_t *args, hsm_hdl_t *session_hdl)
{
	struct hsm_session_hdl_s *s_ptr = NULL;
	struct seco_mu_params mu_params;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t sab_err;

	do {
		if ((args == NULL) || (session_hdl == NULL)) {
			break;
		}

		s_ptr = add_session();
		if (s_ptr == NULL) {
			break;
		}

		s_ptr->phdl = seco_os_abs_open_mu_channel(MU_CHANNEL_HSM, &mu_params);
		if (s_ptr->phdl == NULL) {
			break;
		}

		sab_err = sab_open_session_command(s_ptr->phdl,
						&s_ptr->session_hdl,
						mu_params.mu_id,
						mu_params.interrupt_idx,
						mu_params.tz,
						mu_params.did,
						args->session_priority,
						args->operating_mode);
		err = sab_rating_to_hsm_err(sab_err);
		if (err != HSM_NO_ERROR) {
			break;
		}

		*session_hdl = s_ptr->session_hdl;
	} while (false);

	if (err != HSM_NO_ERROR) {
		if (s_ptr != NULL) {
			if (s_ptr->session_hdl != 0u) {
				(void)hsm_close_session(s_ptr->session_hdl);
			} else if (s_ptr->phdl != NULL) {
				seco_os_abs_close_session(s_ptr->phdl);
				delete_session(s_ptr);
			} else {
				delete_session(s_ptr);
			}
		}
		if (session_hdl != NULL) {
			*session_hdl = 0u; /* force an invalid value.*/
		}
	}

	return err;
}

hsm_err_t hsm_open_key_store_service(hsm_hdl_t session_hdl, 
					open_svc_key_store_args_t *args,
					hsm_hdl_t *key_store_hdl)
{
	struct hsm_session_hdl_s *sess_ptr;
	struct hsm_service_hdl_s *serv_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t sab_err;

	do {
		if ((args == NULL) || (key_store_hdl == NULL)) {
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

		sab_err = sab_open_key_store_command(sess_ptr->phdl,
						session_hdl,
						&serv_ptr->service_hdl,
						args->key_store_identifier,
						args->authentication_nonce,
						args->max_updates_number,
						args->flags);
		err = sab_rating_to_hsm_err(sab_err);
		if (err != HSM_NO_ERROR) {
			delete_service(serv_ptr);
			break;
		}

		*key_store_hdl = serv_ptr->service_hdl;
	} while (false);

	return err;
}

hsm_err_t hsm_close_key_store_service(hsm_hdl_t key_store_hdl)
{
	struct hsm_service_hdl_s *serv_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t sab_err;

	do {
		serv_ptr = service_hdl_to_ptr(key_store_hdl);
		if (serv_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		sab_err = sab_close_key_store(serv_ptr->session->phdl,
						key_store_hdl);
		err = sab_rating_to_hsm_err(sab_err);

		// TODO: delete even in case of error from SECO ?
		delete_service(serv_ptr);

	} while (false);

	return err;
}

hsm_err_t hsm_open_key_management_service(hsm_hdl_t key_store_hdl,
					open_svc_key_management_args_t *args,
					hsm_hdl_t *key_management_hdl)
{
	struct sab_cmd_key_management_open_msg cmd;
	struct sab_cmd_key_management_open_rsp rsp;
	struct hsm_service_hdl_s *key_store_serv_ptr;
	struct hsm_service_hdl_s *key_mgt_serv_ptr;
	int32_t error = 1;
	hsm_err_t err = HSM_GENERAL_ERROR;

	do {
		if ((args == NULL) || (key_management_hdl == NULL)) {
			break;
		}
		key_store_serv_ptr = service_hdl_to_ptr(key_store_hdl);
		if (key_store_serv_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		key_mgt_serv_ptr = add_service(key_store_serv_ptr->session);
		if (key_mgt_serv_ptr == NULL) {
			break;
		}

		seco_fill_cmd_msg_hdr(&cmd.hdr,
			SAB_KEY_MANAGEMENT_OPEN_REQ,
			(uint32_t)sizeof(struct sab_cmd_key_management_open_msg));
		cmd.key_store_handle = key_store_hdl;
		cmd.input_address_ext = 0u;
		cmd.output_address_ext = 0u;
		cmd.flags = args->flags;
		cmd.rsv[0] = 0u;
		cmd.rsv[1] = 0u;
		cmd.rsv[2] = 0u;
		cmd.crc = 0u;
		cmd.crc = seco_compute_msg_crc((uint32_t*)&cmd,
				(uint32_t)(sizeof(cmd) - sizeof(uint32_t)));

		error = seco_send_msg_and_get_resp(key_mgt_serv_ptr->session->phdl,
			(uint32_t *)&cmd,
			(uint32_t)sizeof(struct sab_cmd_key_management_open_msg),
			(uint32_t *)&rsp,
			(uint32_t)sizeof(struct sab_cmd_key_management_open_rsp));
		if (error != 0) {
			delete_service(key_mgt_serv_ptr);
			break;
		}

		err = sab_rating_to_hsm_err(rsp.rsp_code);
		if (err != HSM_NO_ERROR) {
			delete_service(key_mgt_serv_ptr);
			break;
		}

		key_mgt_serv_ptr->service_hdl = rsp.key_management_handle;
		*key_management_hdl = rsp.key_management_handle;
	} while (false);

	return err;
}

hsm_err_t hsm_generate_key(hsm_hdl_t key_management_hdl,
				op_generate_key_args_t *args)
{
	struct sab_cmd_generate_key_msg cmd;
	struct sab_cmd_generate_key_rsp rsp;
	int32_t error = 1;
	struct hsm_service_hdl_s *serv_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;

	do {
		if ((args == NULL) || (args->key_identifier == NULL)) {
			break;
		}
		serv_ptr = service_hdl_to_ptr(key_management_hdl);
		if (serv_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		/* Send the keys store open command to Seco. */
		seco_fill_cmd_msg_hdr(&cmd.hdr,
			SAB_KEY_GENERATE_REQ,
			(uint32_t)sizeof(struct sab_cmd_generate_key_msg));
		cmd.key_management_handle = key_management_hdl;
		cmd.key_identifier = *(args->key_identifier);
		cmd.out_size = args->out_size;
		cmd.flags = args->flags;
		cmd.key_type = args->key_type;
		cmd.key_group = args->key_group;
 		cmd.key_info = args->key_info;
 		cmd.out_key_addr = (uint32_t)seco_os_abs_data_buf(serv_ptr->session->phdl,
				args->out_key,
				args->out_size,
				0u);
 		cmd.crc = 0u;
		cmd.crc = seco_compute_msg_crc((uint32_t*)&cmd,
				(uint32_t)(sizeof(cmd) - sizeof(uint32_t)));

		/* Send the message to Seco. */
		error = seco_send_msg_and_get_resp(serv_ptr->session->phdl,
			(uint32_t *)&cmd,
			(uint32_t)sizeof(struct sab_cmd_generate_key_msg),
			(uint32_t *)&rsp,
			(uint32_t)sizeof(struct sab_cmd_generate_key_rsp));
		if (error != 0) {
			break;
		}

		err = sab_rating_to_hsm_err(rsp.rsp_code);
		if (cmd.flags & HSM_OP_KEY_GENERATION_FLAGS_CREATE) {
			*(args->key_identifier) = rsp.key_identifier;
		}

	} while(false);

	return err;
}

hsm_err_t hsm_manage_key(hsm_hdl_t key_management_hdl,
				op_manage_key_args_t *args)
{
	struct sab_cmd_manage_key_msg cmd;
	struct sab_cmd_manage_key_rsp rsp;
	int32_t error = 1;
	struct hsm_service_hdl_s *serv_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;

	do {
		if ((args == NULL) || (args->key_identifier == NULL)) {
			break;
		}
		serv_ptr = service_hdl_to_ptr(key_management_hdl);
		if (serv_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		/* Send the keys store open command to Seco. */
		seco_fill_cmd_msg_hdr(&cmd.hdr,
			SAB_MANAGE_KEY_REQ,
			(uint32_t)sizeof(struct sab_cmd_manage_key_msg));
		cmd.key_management_handle = key_management_hdl;
		cmd.dest_key_identifier = *(args->key_identifier);
		cmd.kek_id = args->kek_identifier;
		cmd.input_data_size = args->input_size;
		cmd.flags = args->flags;
		cmd.key_type = args->key_type;
		cmd.key_group = args->key_group;
 		cmd.key_info = args->key_info;
		cmd.input_data_addr = (uint32_t)seco_os_abs_data_buf(serv_ptr->session->phdl,
				args->input_data,
				args->input_size,
				DATA_BUF_IS_INPUT);
 		cmd.crc = 0u;
		cmd.crc = seco_compute_msg_crc((uint32_t*)&cmd,
				(uint32_t)(sizeof(cmd) - sizeof(uint32_t)));

		/* Send the message to Seco. */
		error = seco_send_msg_and_get_resp(serv_ptr->session->phdl,
			(uint32_t *)&cmd,
			(uint32_t)sizeof(struct sab_cmd_manage_key_msg),
			(uint32_t *)&rsp,
			(uint32_t)sizeof(struct sab_cmd_manage_key_rsp));
		if (error != 0) {
			break;
		}

		err = sab_rating_to_hsm_err(rsp.rsp_code);
		if (cmd.flags & HSM_OP_MANAGE_KEY_FLAGS_IMPORT_CREATE) {
			*(args->key_identifier) = rsp.key_identifier;
		}

	} while(false);

	return err;
}


hsm_err_t hsm_manage_key_group(hsm_hdl_t key_management_hdl,
				op_manage_key_group_args_t *args)
{
	struct sab_cmd_manage_key_group_msg cmd;
	struct sab_cmd_manage_key_group_rsp rsp;
	int32_t error = 1;
	struct hsm_service_hdl_s *serv_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;

	do {
		if (args == NULL) {
			break;
		}
		serv_ptr = service_hdl_to_ptr(key_management_hdl);
		if (serv_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		/* Send the keys store open command to Seco. */
		seco_fill_cmd_msg_hdr(&cmd.hdr,
			SAB_MANAGE_KEY_GROUP_REQ,
			(uint32_t)sizeof(struct sab_cmd_manage_key_group_msg));
		cmd.key_management_handle = key_management_hdl;
		cmd.key_group = args->key_group;
		cmd.flags = args->flags;
		cmd.rsv = 0;

		/* Send the message to Seco. */
		error = seco_send_msg_and_get_resp(serv_ptr->session->phdl,
			(uint32_t *)&cmd,
			(uint32_t)sizeof(struct sab_cmd_manage_key_group_msg),
			(uint32_t *)&rsp,
			(uint32_t)sizeof(struct sab_cmd_manage_key_group_rsp));
		if (error != 0) {
			break;
		}

		err = sab_rating_to_hsm_err(rsp.rsp_code);

	} while(false);

	return err;
}


hsm_err_t hsm_butterfly_key_expansion(hsm_hdl_t key_management_hdl,
					op_butt_key_exp_args_t *args)
{
	struct sab_cmd_butterfly_key_exp_msg cmd;
	struct sab_cmd_butterfly_key_exp_rsp rsp;
	int32_t error = 1;
	struct hsm_service_hdl_s *serv_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;

	do {
		if ((args == NULL)||(args->dest_key_identifier == NULL)) {
			break;
		}
		serv_ptr = service_hdl_to_ptr(key_management_hdl);
		if (serv_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		/* Send the keys store open command to Seco. */
		seco_fill_cmd_msg_hdr(&cmd.hdr,
			SAB_BUT_KEY_EXP_REQ,
			(uint32_t)sizeof(struct sab_cmd_butterfly_key_exp_msg));
		cmd.key_management_handle = key_management_hdl;
		cmd.key_identifier = args->key_identifier;
		cmd.expansion_function_value_addr = (uint32_t)seco_os_abs_data_buf(serv_ptr->session->phdl,
				args->expansion_function_value,
				args->expansion_function_value_size,
				DATA_BUF_IS_INPUT);
		cmd.hash_value_addr = (uint32_t)seco_os_abs_data_buf(serv_ptr->session->phdl,
				args->hash_value,
				args->hash_value_size,
				DATA_BUF_IS_INPUT);
		cmd.pr_reconstruction_value_addr = (uint32_t)seco_os_abs_data_buf(serv_ptr->session->phdl,
				args->pr_reconstruction_value,
				args->pr_reconstruction_value_size,
				DATA_BUF_IS_INPUT);
		cmd.expansion_function_value_size = args->expansion_function_value_size;
		cmd.hash_value_size = args->hash_value_size;
		cmd.pr_reconstruction_value_size = args->pr_reconstruction_value_size;
		cmd.flags = args->flags;
		cmd.dest_key_identifier = *(args->dest_key_identifier);
		cmd.output_address = (uint32_t)seco_os_abs_data_buf(serv_ptr->session->phdl,
				args->output,
				args->output_size,
				0u);
		cmd.output_size = args->output_size;
		cmd.key_type = args->key_type;
		cmd.rsv = 0u;
		cmd.key_group = args->key_group;
		cmd.key_info = args->key_info;
		cmd.crc = 0u;
		cmd.crc = seco_compute_msg_crc((uint32_t*)&cmd,
				(uint32_t)(sizeof(cmd) - sizeof(uint32_t)));

		/* Send the message to Seco. */
		error = seco_send_msg_and_get_resp(serv_ptr->session->phdl,
			(uint32_t *)&cmd,
			(uint32_t)sizeof(struct sab_cmd_butterfly_key_exp_msg),
			(uint32_t *)&rsp,
			(uint32_t)sizeof(struct sab_cmd_butterfly_key_exp_rsp));
		if (error != 0) {
			break;
		}

		err = sab_rating_to_hsm_err(rsp.rsp_code);
		*(args->dest_key_identifier) = rsp.dest_key_identifier;

	} while(false);

	return err;
}

hsm_err_t hsm_close_key_management_service(hsm_hdl_t key_management_hdl)
{
	struct sab_cmd_key_management_close_msg cmd;
	struct sab_cmd_key_management_close_rsp rsp;
	struct hsm_service_hdl_s *serv_ptr;
	int32_t error = 1;
	hsm_err_t err = HSM_GENERAL_ERROR;

	do {
		serv_ptr = service_hdl_to_ptr(key_management_hdl);
		if (serv_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		seco_fill_cmd_msg_hdr(&cmd.hdr,
			SAB_KEY_MANAGEMENT_CLOSE_REQ,
			(uint32_t)sizeof(struct sab_cmd_key_management_close_msg));
		cmd.key_management_handle = key_management_hdl;


		error = seco_send_msg_and_get_resp(serv_ptr->session->phdl,
			(uint32_t *)&cmd,
			(uint32_t)sizeof(struct sab_cmd_key_management_close_msg),
			(uint32_t *)&rsp,
			(uint32_t)sizeof(struct sab_cmd_key_management_close_rsp));
		if (error == 0) {
			err = sab_rating_to_hsm_err(rsp.rsp_code);
		}

		delete_service(serv_ptr);
	} while (false);

	return err;
}

hsm_err_t hsm_open_cipher_service(hsm_hdl_t key_store_hdl,
					open_svc_cipher_args_t *args,
					hsm_hdl_t *cipher_hdl)
{
	struct hsm_service_hdl_s *key_store_serv_ptr;
	struct hsm_service_hdl_s *cipher_serv_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t sab_err;

	do {
		if ((args == NULL) || (cipher_hdl == NULL)) {
			break;
		}
		key_store_serv_ptr = service_hdl_to_ptr(key_store_hdl);
		if (key_store_serv_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		cipher_serv_ptr = add_service(key_store_serv_ptr->session);
		if (cipher_serv_ptr == NULL) {
			break;
		}

		sab_err = sab_open_cipher(key_store_serv_ptr->session->phdl,
					key_store_hdl,
					&(cipher_serv_ptr->service_hdl),
					args->flags);
		err = sab_rating_to_hsm_err(sab_err);
		if (err != HSM_NO_ERROR) {
			delete_service(cipher_serv_ptr);
			break;
		}
		*cipher_hdl = cipher_serv_ptr->service_hdl;
	} while (false);

	return err;
}


hsm_err_t hsm_close_cipher_service(hsm_hdl_t cipher_hdl)
{
	struct hsm_service_hdl_s *serv_ptr;

	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t sab_err;

	do {
		serv_ptr = service_hdl_to_ptr(cipher_hdl);
		if (serv_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		sab_err = sab_close_cipher(serv_ptr->session->phdl, cipher_hdl);
		err = sab_rating_to_hsm_err(sab_err);

		delete_service(serv_ptr);
	} while (false);

	return err;

}

hsm_err_t hsm_cipher_one_go(hsm_hdl_t cipher_hdl, op_cipher_one_go_args_t* args)
{
	struct hsm_service_hdl_s *serv_ptr;

	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t sab_err;

	do {
		serv_ptr = service_hdl_to_ptr(cipher_hdl);
		if (serv_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		sab_err = sab_cmd_cipher_one_go(serv_ptr->session->phdl,
						cipher_hdl,
						args->key_identifier,
						args->iv,
						args->iv_size,
						args->cipher_algo,
						args->flags,
						args->input,
						args->output,
						args->input_size,
						args->output_size);
		err = sab_rating_to_hsm_err(sab_err);

	} while (false);

	return err;
}

hsm_err_t hsm_ecies_decryption(hsm_hdl_t cipher_hdl, hsm_op_ecies_dec_args_t *args)
{
	struct sab_cmd_ecies_decrypt_msg cmd;
	struct sab_cmd_ecies_decrypt_rsp rsp;
	int32_t error = 1;
	struct hsm_service_hdl_s *serv_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;

	do {
		if (args == NULL) {
			break;
		}
		serv_ptr = service_hdl_to_ptr(cipher_hdl);
		if (serv_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		/* Send the keys store open command to Seco. */
		seco_fill_cmd_msg_hdr(&cmd.hdr,
			SAB_CIPHER_ECIES_DECRYPT_REQ,
			(uint32_t)sizeof(struct sab_cmd_ecies_decrypt_msg));
		cmd.cipher_handle = cipher_hdl;
		cmd.key_id = args->key_identifier;
		cmd.input_address = (uint32_t)seco_os_abs_data_buf(serv_ptr->session->phdl,
				args->input,
				args->input_size,
				DATA_BUF_IS_INPUT);
		cmd.p1_addr = (uint32_t)seco_os_abs_data_buf(serv_ptr->session->phdl,
				args->p1,
				args->p1_size,
				DATA_BUF_IS_INPUT);
		cmd.p2_addr = (uint32_t)seco_os_abs_data_buf(serv_ptr->session->phdl,
				args->p2,
				args->p2_size,
				DATA_BUF_IS_INPUT);
		cmd.output_address = (uint32_t)seco_os_abs_data_buf(serv_ptr->session->phdl,
				args->output,
				args->output_size,
				0u);
		cmd.input_size = args->input_size;
		cmd.output_size = args->output_size;
		cmd.p1_size = args->p1_size;
		cmd.p2_size = args->p2_size;
		cmd.mac_size = args->mac_size;
		cmd.key_type = args->key_type;
		cmd.flags = args->flags;
		cmd.crc = 0u;
		cmd.crc = seco_compute_msg_crc((uint32_t*)&cmd,
				(uint32_t)(sizeof(cmd) - sizeof(uint32_t)));

		/* Send the message to Seco. */
		error = seco_send_msg_and_get_resp(serv_ptr->session->phdl,
			(uint32_t *)&cmd,
			(uint32_t)sizeof(struct sab_cmd_ecies_decrypt_msg),
			(uint32_t *)&rsp,
			(uint32_t)sizeof(struct sab_cmd_ecies_decrypt_rsp));
		if (error != 0) {
			break;
		}

		err = sab_rating_to_hsm_err(rsp.rsp_code);

	} while(false);

	return err;
}

hsm_err_t hsm_open_signature_generation_service(hsm_hdl_t key_store_hdl,
						open_svc_sign_gen_args_t *args,
						hsm_hdl_t *signature_gen_hdl)
{
	struct sab_signature_gen_open_msg cmd;
	struct sab_signature_gen_open_rsp rsp;
	struct hsm_service_hdl_s *key_store_serv_ptr;
	struct hsm_service_hdl_s *sig_gen_serv_ptr;
	int32_t error = 1;
	hsm_err_t err = HSM_GENERAL_ERROR;

	do {
		if ((args == NULL) || (signature_gen_hdl == NULL)) {
			break;
		}
		key_store_serv_ptr = service_hdl_to_ptr(key_store_hdl);
		if (key_store_serv_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		sig_gen_serv_ptr = add_service(key_store_serv_ptr->session);
		if (sig_gen_serv_ptr == NULL) {
			break;
		}

		seco_fill_cmd_msg_hdr(&cmd.hdr,
			SAB_SIGNATURE_GENERATION_OPEN_REQ,
			(uint32_t)sizeof(struct sab_signature_gen_open_msg));
		cmd.key_store_hdl = key_store_hdl;
		cmd.input_address_ext = 0u;
		cmd.output_address_ext = 0u;
		cmd.flags = args->flags;
		cmd.reserved[0] = 0u;
		cmd.reserved[1] = 0u;
		cmd.reserved[2] = 0u;
		cmd.crc = 0u;
		cmd.crc = seco_compute_msg_crc((uint32_t*)&cmd,
				(uint32_t)(sizeof(cmd) - sizeof(uint32_t)));

		error = seco_send_msg_and_get_resp(key_store_serv_ptr->session->phdl,
			(uint32_t *)&cmd,
			(uint32_t)sizeof(struct sab_signature_gen_open_msg),
			(uint32_t *)&rsp,
			(uint32_t)sizeof(struct sab_signature_gen_open_rsp));
		if (error != 0) {
			delete_service(sig_gen_serv_ptr);
			break;
		}

		err = sab_rating_to_hsm_err(rsp.rsp_code);
		if (err != HSM_NO_ERROR) {
			delete_service(sig_gen_serv_ptr);
			break;
		}
		sig_gen_serv_ptr->service_hdl = rsp.sig_gen_hdl;
		*signature_gen_hdl = rsp.sig_gen_hdl;
	} while (false);

	return err;
}

hsm_err_t hsm_close_signature_generation_service(hsm_hdl_t signature_gen_hdl)
{
	struct sab_signature_gen_close_msg cmd;
	struct sab_signature_gen_close_rsp rsp;
	struct hsm_service_hdl_s *serv_ptr;
	int32_t error = 1;
	hsm_err_t err = HSM_GENERAL_ERROR;

	do {
		serv_ptr = service_hdl_to_ptr(signature_gen_hdl);
		if (serv_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		seco_fill_cmd_msg_hdr(&cmd.hdr,
			SAB_SIGNATURE_GENERATION_CLOSE_REQ,
			(uint32_t)sizeof(struct sab_signature_gen_close_msg));
		cmd.sig_gen_hdl = signature_gen_hdl;


		error = seco_send_msg_and_get_resp(serv_ptr->session->phdl,
			(uint32_t *)&cmd,
			(uint32_t)sizeof(struct sab_signature_gen_close_msg),
			(uint32_t *)&rsp,
			(uint32_t)sizeof(struct sab_signature_gen_close_rsp));
		if (error == 0) {
			err = sab_rating_to_hsm_err(rsp.rsp_code);
		}
		delete_service(serv_ptr);
	} while (false);

	return err;
}

hsm_err_t hsm_generate_signature(hsm_hdl_t signature_gen_hdl,
					op_generate_sign_args_t *args)
{
	struct sab_signature_generate_msg cmd;
	struct sab_signature_generate_rsp rsp;
	int32_t error = 1;
	struct hsm_service_hdl_s *serv_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;

	do {
		if (args == NULL) {
			break;
		}
		serv_ptr = service_hdl_to_ptr(signature_gen_hdl);
		if (serv_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		/* Send the keys store open command to Seco. */
		seco_fill_cmd_msg_hdr(&cmd.hdr,
			SAB_SIGNATURE_GENERATE_REQ,
			(uint32_t)sizeof(struct sab_signature_generate_msg));
		cmd.sig_gen_hdl = signature_gen_hdl;
		cmd.key_identifier = args->key_identifier;
		cmd.message_addr = (uint32_t)seco_os_abs_data_buf(serv_ptr->session->phdl,
					args->message,
					args->message_size,
					DATA_BUF_IS_INPUT);
		cmd.signature_addr = (uint32_t)seco_os_abs_data_buf(serv_ptr->session->phdl,
					args->signature,
					args->signature_size,
					0u);
		cmd.message_size = args->message_size;
		cmd.signature_size = args->signature_size;
		cmd.scheme_id = args->scheme_id;
		cmd.flags = args->flags;
		cmd.crc = 0u;
		cmd.crc = seco_compute_msg_crc((uint32_t*)&cmd,
				(uint32_t)(sizeof(cmd) - sizeof(uint32_t)));

		/* Send the message to Seco. */
		error = seco_send_msg_and_get_resp(serv_ptr->session->phdl,
			(uint32_t *)&cmd,
			(uint32_t)sizeof(struct sab_signature_generate_msg),
			(uint32_t *)&rsp,
			(uint32_t)sizeof(struct sab_signature_generate_rsp));
		if (error != 0) {
			break;
		}

		err = sab_rating_to_hsm_err(rsp.rsp_code);
	} while(false);

	return err;
}

hsm_err_t hsm_prepare_signature(hsm_hdl_t signature_gen_hdl,
				op_prepare_sign_args_t *args)
{
	struct sab_prepare_signature_msg cmd;
	struct sab_prepare_signature_rsp rsp;
	int32_t error = 1;
	struct hsm_service_hdl_s *serv_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;

	do {
		if (args == NULL) {
			break;
		}
		serv_ptr = service_hdl_to_ptr(signature_gen_hdl);
		if (serv_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		/* Send the keys store open command to Seco. */
		seco_fill_cmd_msg_hdr(&cmd.hdr,
			SAB_SIGNATURE_PREPARE_REQ,
			(uint32_t)sizeof(struct sab_prepare_signature_msg));
		cmd.sig_gen_hdl = signature_gen_hdl;
		cmd.scheme_id = args->scheme_id;
		cmd.flags = args->flags;
		cmd.reserved = 0u;

		/* Send the message to Seco. */
		error = seco_send_msg_and_get_resp(serv_ptr->session->phdl,
			(uint32_t *)&cmd,
			(uint32_t)sizeof(struct sab_prepare_signature_msg),
			(uint32_t *)&rsp,
			(uint32_t)sizeof(struct sab_prepare_signature_rsp));
		if (error != 0) {
			break;
		}

		err = sab_rating_to_hsm_err(rsp.rsp_code);
	} while(false);

	return err;
}

hsm_err_t hsm_open_signature_verification_service(hsm_hdl_t session_hdl,
						open_svc_sign_ver_args_t *args,
						hsm_hdl_t *signature_ver_hdl)
{
	struct sab_signature_verif_open_msg cmd;
	struct sab_signature_verif_open_rsp rsp;
	struct hsm_session_hdl_s *sess_ptr;
	struct hsm_service_hdl_s *serv_ptr;
	int32_t error = 1;
	hsm_err_t err = HSM_GENERAL_ERROR;

	do {
		if ((args == NULL) || (signature_ver_hdl == NULL)) {
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

		seco_fill_cmd_msg_hdr(&cmd.hdr,
			SAB_SIGNATURE_VERIFICATION_OPEN_REQ,
			(uint32_t)sizeof(struct sab_signature_verif_open_msg));
		cmd.session_handle = session_hdl;
		cmd.input_address_ext = 0u;
		cmd.output_address_ext = 0u;
		cmd.flags = args->flags;
		cmd.reserved[0] = 0u;
		cmd.reserved[1] = 0u;
		cmd.reserved[2] = 0u;
		cmd.crc = 0u;
		cmd.crc = seco_compute_msg_crc((uint32_t*)&cmd,
				(uint32_t)(sizeof(cmd) - sizeof(uint32_t)));

		error = seco_send_msg_and_get_resp(sess_ptr->phdl,
			(uint32_t *)&cmd,
			(uint32_t)sizeof(struct sab_signature_verif_open_msg),
			(uint32_t *)&rsp,
			(uint32_t)sizeof(struct sab_signature_verif_open_rsp));
		if (error != 0) {
			delete_service(serv_ptr);
			break;
		}

		err = sab_rating_to_hsm_err(rsp.rsp_code);
		if (err != HSM_NO_ERROR) {
			delete_service(serv_ptr);
			break;
		}
		serv_ptr->service_hdl = rsp.sig_ver_hdl;
		*signature_ver_hdl = rsp.sig_ver_hdl;
	} while (false);

	return err;
}

hsm_err_t hsm_close_signature_verification_service(hsm_hdl_t signature_ver_hdl)
{
	struct sab_signature_verif_close_msg cmd;
	struct sab_signature_verif_close_rsp rsp;
	struct hsm_service_hdl_s *serv_ptr;
	int32_t error = 1;
	hsm_err_t err = HSM_GENERAL_ERROR;

	do {
		serv_ptr = service_hdl_to_ptr(signature_ver_hdl);
		if (serv_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		seco_fill_cmd_msg_hdr(&cmd.hdr,
			SAB_SIGNATURE_VERIFICATION_CLOSE_REQ,
			(uint32_t)sizeof(struct sab_signature_verif_close_msg));
		cmd.sig_ver_hdl = signature_ver_hdl;

		error = seco_send_msg_and_get_resp(serv_ptr->session->phdl,
			(uint32_t *)&cmd,
			(uint32_t)sizeof(struct sab_signature_verif_close_msg),
			(uint32_t *)&rsp,
			(uint32_t)sizeof(struct sab_signature_verif_close_rsp));
		if (error == 0) {
			err = sab_rating_to_hsm_err(rsp.rsp_code);
		}
		delete_service(serv_ptr);
	} while (false);

	return err;
}

hsm_err_t hsm_verify_signature(hsm_hdl_t signature_ver_hdl,
				op_verify_sign_args_t *args,
				hsm_verification_status_t *status)
{
	struct sab_signature_verify_msg cmd;
	struct sab_signature_verify_rsp rsp;
	int32_t error = 1;
	struct hsm_service_hdl_s *serv_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;

	do {
		if ((args == NULL) || (status == NULL)) {
			break;
		}
		serv_ptr = service_hdl_to_ptr(signature_ver_hdl);
		if (serv_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		/* Send the keys store open command to Seco. */
		seco_fill_cmd_msg_hdr(&cmd.hdr,
			SAB_SIGNATURE_VERIFY_REQ,
			(uint32_t)sizeof(struct sab_signature_verify_msg));
		cmd.sig_ver_hdl = signature_ver_hdl;
		cmd.key_addr = (uint32_t)seco_os_abs_data_buf(serv_ptr->session->phdl,
					args->key,
					args->key_size,
					DATA_BUF_IS_INPUT);
		cmd.msg_addr = (uint32_t)seco_os_abs_data_buf(serv_ptr->session->phdl,
					args->message,
					args->message_size,
					DATA_BUF_IS_INPUT);
		cmd.sig_addr = (uint32_t)seco_os_abs_data_buf(serv_ptr->session->phdl,
					args->signature,
					args->signature_size,
					DATA_BUF_IS_INPUT);
		cmd.key_size = args->key_size;
		cmd.sig_size = args->signature_size;
		cmd.message_size = args->message_size;
		cmd.sig_scheme = args->scheme_id;
		cmd.flags = args->flags;
		cmd.reserved = 0u;
		cmd.crc = 0u;
		cmd.crc = seco_compute_msg_crc((uint32_t*)&cmd,
				(uint32_t)(sizeof(cmd) - sizeof(uint32_t)));

		/* Send the message to Seco. */
		error = seco_send_msg_and_get_resp(serv_ptr->session->phdl,
			(uint32_t *)&cmd,
			(uint32_t)sizeof(struct sab_signature_verify_msg),
			(uint32_t *)&rsp,
			(uint32_t)sizeof(struct sab_signature_verify_rsp));
		if (error != 0) {
			break;
		}

		err = sab_rating_to_hsm_err(rsp.rsp_code);
		*status = rsp.verification_status;
	} while(false);

	return err;
}

hsm_err_t hsm_import_public_key(hsm_hdl_t signature_ver_hdl,
				op_import_public_key_args_t *args,
				uint32_t *key_ref)
{
	struct sab_import_pub_key_msg cmd;
	struct sab_import_pub_key_rsp rsp;
	int32_t error = 1;
	struct hsm_service_hdl_s *serv_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;

	do {
		if ((args == NULL) || (key_ref == NULL)) {
			break;
		}

		serv_ptr = service_hdl_to_ptr(signature_ver_hdl);
		if (serv_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		/* Send the keys store open command to Seco. */
		seco_fill_cmd_msg_hdr(&cmd.hdr,
			SAB_IMPORT_PUB_KEY,
			(uint32_t)sizeof(struct sab_import_pub_key_msg));
		cmd.sig_ver_hdl = signature_ver_hdl;
		cmd.key_addr = (uint32_t)seco_os_abs_data_buf(serv_ptr->session->phdl,
					args->key,
					args->key_size,
					DATA_BUF_IS_INPUT);
		cmd.key_size = args->key_size;
		cmd.key_type = args->key_type;
		cmd.flags = args->flags;

		/* Send the message to Seco. */
		error = seco_send_msg_and_get_resp(serv_ptr->session->phdl,
			(uint32_t *)&cmd,
			(uint32_t)sizeof(struct sab_import_pub_key_msg),
			(uint32_t *)&rsp,
			(uint32_t)sizeof(struct sab_import_pub_key_rsp));
		if (error != 0) {
			break;
		}

		err = sab_rating_to_hsm_err(rsp.rsp_code);
		*key_ref = rsp.key_ref;
	} while(false);

	return err;
}

hsm_err_t hsm_open_rng_service(hsm_hdl_t session_hdl,
				open_svc_rng_args_t *args,
				hsm_hdl_t *rng_hdl)
{
	struct hsm_session_hdl_s *sess_ptr;
	struct hsm_service_hdl_s *serv_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t sab_err;

	do {
		if ((args == NULL) || (rng_hdl == NULL)) {
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

		sab_err = sab_open_rng(sess_ptr->phdl,
					session_hdl,
					&(serv_ptr->service_hdl),
					args->flags);
		err = sab_rating_to_hsm_err(sab_err);
		if (err != HSM_NO_ERROR) {
			delete_service(serv_ptr);
			break;
		}
		*rng_hdl = serv_ptr->service_hdl;
	} while (false);

	return err;
}

hsm_err_t hsm_close_rng_service(hsm_hdl_t rng_hdl)
{
	struct hsm_service_hdl_s *serv_ptr;

	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t sab_err;

	do {
		serv_ptr = service_hdl_to_ptr(rng_hdl);
		if (serv_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		sab_err = sab_close_rng(serv_ptr->session->phdl, rng_hdl);
		err = sab_rating_to_hsm_err(sab_err);

		delete_service(serv_ptr);
	} while (false);

	return err;
}

hsm_err_t hsm_get_random(hsm_hdl_t rng_hdl, op_get_random_args_t *args)
{
	struct sab_cmd_get_rnd_msg cmd;
	struct sab_cmd_get_rnd_rsp rsp;
	int32_t error = 1;
	struct hsm_service_hdl_s *serv_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;

	do {
		if (args == NULL) {
			break;
		}

		serv_ptr = service_hdl_to_ptr(rng_hdl);
		if (serv_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		/* Send the keys store open command to Seco. */
		seco_fill_cmd_msg_hdr(&cmd.hdr,
			SAB_RNG_GET_RANDOM,
			(uint32_t)sizeof(struct sab_cmd_get_rnd_msg));
		cmd.rng_handle = rng_hdl;
		cmd.rnd_addr = (uint32_t)seco_os_abs_data_buf(serv_ptr->session->phdl,
					args->output,
					args->random_size,
					0u);
		cmd.rnd_size = args->random_size;

		/* Send the message to Seco. */
		error = seco_send_msg_and_get_resp(serv_ptr->session->phdl,
			(uint32_t *)&cmd,
			(uint32_t)sizeof(struct sab_cmd_get_rnd_msg),
			(uint32_t *)&rsp,
			(uint32_t)sizeof(struct sab_cmd_get_rnd_rsp));
		if (error != 0) {
			break;
		}

		err = sab_rating_to_hsm_err(rsp.rsp_code);
	} while(false);

	return err;
}

hsm_err_t hsm_open_hash_service(hsm_hdl_t session_hdl,
				open_svc_hash_args_t *args,
				hsm_hdl_t *hash_hdl)
{
	struct sab_hash_open_msg cmd;
	struct sab_hash_open_rsp rsp;
	struct hsm_session_hdl_s *sess_ptr;
	struct hsm_service_hdl_s *serv_ptr;
	int32_t error = 1;
	hsm_err_t err = HSM_GENERAL_ERROR;

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

		seco_fill_cmd_msg_hdr(&cmd.hdr,
			SAB_HASH_OPEN_REQ,
			(uint32_t)sizeof(struct sab_hash_open_msg));
		cmd.session_handle = session_hdl;
		cmd.input_address_ext = 0u;
		cmd.output_address_ext = 0u;
		cmd.flags = args->flags;
		cmd.reserved[0] = 0u;
		cmd.reserved[1] = 0u;
		cmd.reserved[2] = 0u;
		cmd.crc = 0u;
		cmd.crc = seco_compute_msg_crc((uint32_t*)&cmd,
				(uint32_t)(sizeof(cmd) - sizeof(uint32_t)));

		error = seco_send_msg_and_get_resp(sess_ptr->phdl,
			(uint32_t *)&cmd,
			(uint32_t)sizeof(struct sab_hash_open_msg),
			(uint32_t *)&rsp,
			(uint32_t)sizeof(struct sab_hash_open_rsp));
		if (error != 0) {
			delete_service(serv_ptr);
			break;
		}

		err = sab_rating_to_hsm_err(rsp.rsp_code);
		if (err != HSM_NO_ERROR) {
			delete_service(serv_ptr);
			break;
		}
		serv_ptr->service_hdl = rsp.hash_hdl;
		*hash_hdl = rsp.hash_hdl;
	} while (false);

	return err;
}

hsm_err_t hsm_close_hash_service(hsm_hdl_t hash_hdl)
{
	struct sab_hash_close_msg cmd;
	struct sab_hash_close_rsp rsp;
	struct hsm_service_hdl_s *serv_ptr;
	int32_t error = 1;
	hsm_err_t err = HSM_GENERAL_ERROR;

	do {
		serv_ptr = service_hdl_to_ptr(hash_hdl);
		if (serv_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		seco_fill_cmd_msg_hdr(&cmd.hdr,
			SAB_HASH_CLOSE_REQ,
			(uint32_t)sizeof(struct sab_hash_close_msg));
		cmd.hash_hdl = hash_hdl;


		error = seco_send_msg_and_get_resp(serv_ptr->session->phdl,
			(uint32_t *)&cmd,
			(uint32_t)sizeof(struct sab_hash_close_msg),
			(uint32_t *)&rsp,
			(uint32_t)sizeof(struct sab_hash_close_rsp));
		if (error == 0) {
			err = sab_rating_to_hsm_err(rsp.rsp_code);
		}
		delete_service(serv_ptr);
	} while (false);

	return err;
}

hsm_err_t hsm_hash_one_go(hsm_hdl_t hash_hdl, op_hash_one_go_args_t *args)
{
	struct sab_hash_one_go_msg cmd;
	struct sab_hash_one_go_rsp rsp;
	int32_t error = 1;
	struct hsm_service_hdl_s *serv_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;

	do {
		if (args == NULL) {
			break;
		}

		serv_ptr = service_hdl_to_ptr(hash_hdl);
		if (serv_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		/* Send the keys store open command to Seco. */
		seco_fill_cmd_msg_hdr(&cmd.hdr,
			SAB_HASH_ONE_GO_REQ,
			(uint32_t)sizeof(struct sab_hash_one_go_msg));

		cmd.hash_hdl = hash_hdl;
		cmd.input_addr = (uint32_t)seco_os_abs_data_buf(serv_ptr->session->phdl,
					args->input,
					args->input_size,
					DATA_BUF_IS_INPUT);
		cmd.output_addr = (uint32_t)seco_os_abs_data_buf(serv_ptr->session->phdl,
					args->output,
					args->output_size,
					0u);
		cmd.input_size = args->input_size;
		cmd.output_size = args->output_size;
		cmd.algo = args->algo;
		cmd.flags = args->flags;
		cmd.reserved = 0u;
		cmd.crc = 0u;
		cmd.crc = seco_compute_msg_crc((uint32_t*)&cmd,
				(uint32_t)(sizeof(cmd) - sizeof(uint32_t)));
		/* Send the message to Seco. */
		error = seco_send_msg_and_get_resp(serv_ptr->session->phdl,
			(uint32_t *)&cmd,
			(uint32_t)sizeof(struct sab_hash_one_go_msg),
			(uint32_t *)&rsp,
			(uint32_t)sizeof(struct sab_hash_one_go_rsp));
		if (error != 0) {
			break;
		}

		err = sab_rating_to_hsm_err(rsp.rsp_code);
	} while(false);

	return err;
}

hsm_err_t hsm_pub_key_reconstruction(hsm_hdl_t session_hdl,
					hsm_op_pub_key_rec_args_t *args)
{
	struct sab_public_key_reconstruct_msg cmd;
	struct sab_public_key_reconstruct_rsp rsp;
	int32_t error = 1;
	struct hsm_session_hdl_s *sess_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;

	do {
		sess_ptr = session_hdl_to_ptr(session_hdl);
		if (sess_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		/* Send the keys store open command to Seco. */
		seco_fill_cmd_msg_hdr(&cmd.hdr,
			SAB_PUB_KEY_RECONSTRUCTION_REQ,
			(uint32_t)sizeof(struct sab_public_key_reconstruct_msg));
		cmd.sesssion_handle = session_hdl;
		cmd.pu_address_ext = 0u;
		cmd.pu_address = (uint32_t)seco_os_abs_data_buf(sess_ptr->phdl,
					args->pub_rec,
					args->pub_rec_size,
					DATA_BUF_IS_INPUT);
		cmd.hash_address_ext = 0u;
		cmd.hash_address = (uint32_t)seco_os_abs_data_buf(sess_ptr->phdl,
					args->hash,
					args->hash_size,
					DATA_BUF_IS_INPUT);
		cmd.ca_key_address_ext = 0u;
		cmd.ca_key_address = (uint32_t)seco_os_abs_data_buf(sess_ptr->phdl,
					args->ca_key,
					args->ca_key_size,
					DATA_BUF_IS_INPUT);
		cmd.out_key_address_ext = 0u;
		cmd.out_key_address = (uint32_t)seco_os_abs_data_buf(sess_ptr->phdl,
					args->out_key,
					args->out_key_size,
					0u);
		cmd.pu_size = args->pub_rec_size;
		cmd.hash_size = args->hash_size;
		cmd.ca_key_size = args->ca_key_size;
		cmd.out_key_size = args->out_key_size;
		cmd.key_type = args->key_type;
		cmd.flags = args->flags;
		cmd.rsv = 0u;
		cmd.crc = 0u;
		cmd.crc = seco_compute_msg_crc((uint32_t*)&cmd,
				(uint32_t)(sizeof(cmd) - sizeof(uint32_t)));

		/* Send the message to Seco. */
		error = seco_send_msg_and_get_resp(sess_ptr->phdl,
			(uint32_t *)&cmd,
			(uint32_t)sizeof(struct sab_public_key_reconstruct_msg),
			(uint32_t *)&rsp,
			(uint32_t)sizeof(struct sab_public_key_reconstruct_rsp));
		if (error != 0) {
			break;
		}

		err = sab_rating_to_hsm_err(rsp.rsp_code);
	} while(false);

	return err;
}

hsm_err_t hsm_pub_key_decompression(hsm_hdl_t session_hdl,
					hsm_op_pub_key_dec_args_t *args)
{
	struct sab_public_key_decompression_msg cmd;
	struct sab_public_key_decompression_rsp rsp;
	int32_t error = 1;
	struct hsm_session_hdl_s *sess_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;

	do {
		sess_ptr = session_hdl_to_ptr(session_hdl);
		if (sess_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		/* Send the keys store open command to Seco. */
		seco_fill_cmd_msg_hdr(&cmd.hdr,
			SAB_PUB_KEY_DECOMPRESSION_REQ,
			(uint32_t)sizeof(struct sab_public_key_decompression_msg));
		cmd.sesssion_handle = session_hdl;
		cmd.input_address_ext = 0u;
		cmd.input_address = (uint32_t)seco_os_abs_data_buf(sess_ptr->phdl,
					args->key,
					args->key_size,
					DATA_BUF_IS_INPUT);
		cmd.output_address_ext = 0u;
		cmd.output_address = (uint32_t)seco_os_abs_data_buf(sess_ptr->phdl,
					args->out_key,
					args->out_key_size,
					0u);
		cmd.input_size = args->key_size;
		cmd.out_size = args->out_key_size;
		cmd.key_type = args->key_type;
		cmd.flags = args->flags;
		cmd.rsv = 0u;
		cmd.crc = 0u;
		cmd.crc = seco_compute_msg_crc((uint32_t*)&cmd,
				(uint32_t)(sizeof(cmd) - sizeof(uint32_t)));

		/* Send the message to Seco. */
		error = seco_send_msg_and_get_resp(sess_ptr->phdl,
			(uint32_t *)&cmd,
			(uint32_t)sizeof(struct sab_public_key_decompression_msg),
			(uint32_t *)&rsp,
			(uint32_t)sizeof(struct sab_public_key_decompression_rsp));
		if (error != 0) {
			break;
		}

		err = sab_rating_to_hsm_err(rsp.rsp_code);
	} while(false);

	return err;
}

hsm_err_t hsm_ecies_encryption(hsm_hdl_t session_hdl, hsm_op_ecies_enc_args_t *args)
{
	struct sab_cmd_ecies_encrypt_msg cmd;
	struct sab_cmd_ecies_encrypt_rsp rsp;
	int32_t error = 1;
	struct hsm_session_hdl_s *sess_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;

	do {
		sess_ptr = session_hdl_to_ptr(session_hdl);
		if (sess_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		/* Send the keys store open command to Seco. */
		seco_fill_cmd_msg_hdr(&cmd.hdr,
			SAB_ECIES_ENC_REQ,
			(uint32_t)sizeof(struct sab_cmd_ecies_encrypt_msg));
		cmd.sesssion_handle = session_hdl;
		cmd.input_addr_ext = 0u;
		cmd.input_addr = (uint32_t)seco_os_abs_data_buf(sess_ptr->phdl,
					args->input,
					args->input_size,
					DATA_BUF_IS_INPUT);
		cmd.key_addr_ext = 0u;
		cmd.key_addr = (uint32_t)seco_os_abs_data_buf(sess_ptr->phdl,
					args->pub_key,
					args->pub_key_size,
					DATA_BUF_IS_INPUT);
		cmd.p1_addr_ext = 0u;
		cmd.p1_addr = (uint32_t)seco_os_abs_data_buf(sess_ptr->phdl,
					args->p1,
					args->p1_size,
					DATA_BUF_IS_INPUT);
		cmd.p2_addr_ext = 0u;
		cmd.p2_addr = (uint32_t)seco_os_abs_data_buf(sess_ptr->phdl,
					args->p2,
					args->p2_size,
					DATA_BUF_IS_INPUT);
		cmd.output_addr_ext = 0u;
		cmd.output_addr = (uint32_t)seco_os_abs_data_buf(sess_ptr->phdl,
					args->output,
					args->out_size,
					0u);
		cmd.input_size = args->input_size;
		cmd.p1_size = args->p1_size;
		cmd.p2_size = args->p2_size;
		cmd.key_size = args->pub_key_size;
		cmd.mac_size = args->mac_size;
		cmd.output_size = args->out_size;
		cmd.key_type = args->key_type;
		cmd.flags = args->flags;
		cmd.reserved = 0u;
		cmd.crc = 0u;
		cmd.crc = seco_compute_msg_crc((uint32_t*)&cmd,
				(uint32_t)(sizeof(cmd) - sizeof(uint32_t)));

		/* Send the message to Seco. */
		error = seco_send_msg_and_get_resp(sess_ptr->phdl,
			(uint32_t *)&cmd,
			(uint32_t)sizeof(struct sab_cmd_ecies_encrypt_msg),
			(uint32_t *)&rsp,
			(uint32_t)sizeof(struct sab_cmd_ecies_encrypt_rsp));
		if (error != 0) {
			break;
		}

		err = sab_rating_to_hsm_err(rsp.rsp_code);
	} while(false);

	return err;
}

hsm_err_t hsm_pub_key_recovery(hsm_hdl_t key_store_hdl, hsm_op_pub_key_recovery_args_t *args)
{
	struct sab_cmd_pub_key_recovery_msg cmd;
	struct sab_cmd_pub_key_recovery_rsp rsp;
	int32_t error = 1;
	struct hsm_service_hdl_s *key_store_serv_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;

	do {
		key_store_serv_ptr = service_hdl_to_ptr(key_store_hdl);
		if (key_store_serv_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		seco_fill_cmd_msg_hdr(&cmd.hdr,
			SAB_PUB_KEY_RECOVERY_REQ,
			(uint32_t)sizeof(struct sab_cmd_pub_key_recovery_msg));
		cmd.key_store_handle = key_store_hdl;
		cmd.key_identifier = args->key_identifier;
		cmd.out_key_addr_ext = 0u;
		cmd.out_key_addr = (uint32_t)seco_os_abs_data_buf(key_store_serv_ptr->session->phdl,
					args->out_key,
					args->out_key_size,
					0u);
		cmd.out_key_size = args->out_key_size;
		cmd.key_type = args->key_type;
		cmd.flags = args->flags;
		cmd.crc = 0u;
		cmd.crc = seco_compute_msg_crc((uint32_t*)&cmd,
				(uint32_t)(sizeof(cmd) - sizeof(uint32_t)));

		/* Send the message to Seco. */
		error = seco_send_msg_and_get_resp(key_store_serv_ptr->session->phdl,
			(uint32_t *)&cmd,
			(uint32_t)sizeof(struct sab_cmd_pub_key_recovery_msg),
			(uint32_t *)&rsp,
			(uint32_t)sizeof(struct sab_cmd_pub_key_recovery_rsp));
		if (error != 0) {
			break;
		}

		err = sab_rating_to_hsm_err(rsp.rsp_code);
	} while(false);

	return err;
}

hsm_err_t hsm_open_data_storage_service(hsm_hdl_t key_store_hdl,
					open_svc_data_storage_args_t *args,
					hsm_hdl_t *data_storage_hdl)
{
	struct sab_cmd_data_storage_open_msg cmd;
	struct sab_cmd_data_storage_open_rsp rsp;
	struct hsm_service_hdl_s *key_store_serv_ptr;
	struct hsm_service_hdl_s *data_storage_serv_ptr;
	int32_t error = 1;
	hsm_err_t err = HSM_GENERAL_ERROR;

	do {
		if ((args == NULL) || (data_storage_hdl == NULL)) {
			break;
		}
		key_store_serv_ptr = service_hdl_to_ptr(key_store_hdl);
		if (key_store_serv_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		data_storage_serv_ptr = add_service(key_store_serv_ptr->session);
		if (data_storage_serv_ptr == NULL) {
			break;
		}

		seco_fill_cmd_msg_hdr(&cmd.hdr,
			SAB_DATA_STORAGE_OPEN_REQ,
			(uint32_t)sizeof(struct sab_cmd_data_storage_open_msg));
		cmd.key_store_handle = key_store_hdl;
		cmd.input_address_ext = 0u;
		cmd.output_address_ext = 0u;
		cmd.flags = args->flags;
		cmd.rsv[0] = 0u;
		cmd.rsv[1] = 0u;
		cmd.rsv[2] = 0u;
		cmd.crc = 0u;
		cmd.crc = seco_compute_msg_crc((uint32_t*)&cmd,
				(uint32_t)(sizeof(cmd) - sizeof(uint32_t)));

		error = seco_send_msg_and_get_resp(data_storage_serv_ptr->session->phdl,
			(uint32_t *)&cmd,
			(uint32_t)sizeof(struct sab_cmd_data_storage_open_msg),
			(uint32_t *)&rsp,
			(uint32_t)sizeof(struct sab_cmd_data_storage_open_rsp));
		if (error != 0) {
			delete_service(data_storage_serv_ptr);
			break;
		}

		err = sab_rating_to_hsm_err(rsp.rsp_code);
		if (err != HSM_NO_ERROR) {
			delete_service(data_storage_serv_ptr);
			break;
		}

		data_storage_serv_ptr->service_hdl = rsp.data_storage_handle;
		*data_storage_hdl = rsp.data_storage_handle;
	} while (false);

	return err;
}

hsm_err_t hsm_close_data_storage_service(hsm_hdl_t data_storage_hdl)
{
	struct sab_cmd_data_storage_close_msg cmd;
	struct sab_cmd_data_storage_close_rsp rsp;
	struct hsm_service_hdl_s *serv_ptr;
	int32_t error = 1;
	hsm_err_t err = HSM_GENERAL_ERROR;

	do {
		serv_ptr = service_hdl_to_ptr(data_storage_hdl);
		if (serv_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		seco_fill_cmd_msg_hdr(&cmd.hdr,
			SAB_DATA_STORAGE_CLOSE_REQ,
			(uint32_t)sizeof(struct sab_cmd_data_storage_close_msg));
		cmd.data_storage_handle = data_storage_hdl;


		error = seco_send_msg_and_get_resp(serv_ptr->session->phdl,
			(uint32_t *)&cmd,
			(uint32_t)sizeof(struct sab_cmd_data_storage_close_msg),
			(uint32_t *)&rsp,
			(uint32_t)sizeof(struct sab_cmd_data_storage_close_rsp));
		if (error == 0) {
			err = sab_rating_to_hsm_err(rsp.rsp_code);
		}

		delete_service(serv_ptr);
	} while (false);

	return err;
}

hsm_err_t hsm_data_storage(hsm_hdl_t data_storage_hdl,
				op_data_storage_args_t *args)
{
	struct sab_cmd_data_storage_msg cmd;
	struct sab_cmd_data_storage_rsp rsp;
	int32_t error = 1;
	struct hsm_service_hdl_s *serv_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;

	do {
		if (args == NULL) {
			break;
		}
		serv_ptr = service_hdl_to_ptr(data_storage_hdl);
		if (serv_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		/* Send the data storage command to Seco. */
		seco_fill_cmd_msg_hdr(&cmd.hdr,
			SAB_DATA_STORAGE_REQ,
			(uint32_t)sizeof(struct sab_cmd_data_storage_msg));
		cmd.data_storage_handle = data_storage_hdl;
		cmd.data_address = (uint32_t)seco_os_abs_data_buf(serv_ptr->session->phdl,
					args->data,
					args->data_size,
					((args->flags & HSM_OP_DATA_STORAGE_FLAGS_STORE)? DATA_BUF_IS_INPUT : 0));
		cmd.data_size = args->data_size;
		cmd.data_id = args->data_id;
		cmd.flags = args->flags;
		cmd.rsv = 0u;
 		cmd.crc = 0u;
		cmd.crc = seco_compute_msg_crc((uint32_t*)&cmd,
				(uint32_t)(sizeof(cmd) - sizeof(uint32_t)));

		/* Send the message to Seco. */
		error = seco_send_msg_and_get_resp(serv_ptr->session->phdl,
			(uint32_t *)&cmd,
			(uint32_t)sizeof(struct sab_cmd_data_storage_msg),
			(uint32_t *)&rsp,
			(uint32_t)sizeof(struct sab_cmd_data_storage_rsp));
		if (error != 0) {
			break;
		}

		err = sab_rating_to_hsm_err(rsp.rsp_code);

	} while(false);

	return err;
}

hsm_err_t hsm_auth_enc(hsm_hdl_t cipher_hdl, op_auth_enc_args_t* args)
{
	struct sab_cmd_auth_enc_msg cmd;
	struct sab_cmd_auth_enc_rsp rsp;
	struct hsm_service_hdl_s *serv_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;
	uint32_t sab_err = 1;

	do {
		if (args == NULL) {
			break;
		}

		serv_ptr = service_hdl_to_ptr(cipher_hdl);
		if (serv_ptr == NULL) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		/* Fill the authenticated encryption command */
		seco_fill_cmd_msg_hdr(&cmd.hdr,
			SAB_AUTH_ENC_REQ,
			(uint32_t)sizeof(struct sab_cmd_auth_enc_msg));

		cmd.cipher_handle = cipher_hdl;
		cmd.key_id = args->key_identifier;
		cmd.iv_address = (uint32_t)seco_os_abs_data_buf(serv_ptr->session->phdl,
								args->iv, args->iv_size, DATA_BUF_IS_INPUT);
		cmd.iv_size = args->iv_size;
		cmd.aad_address = (uint32_t)seco_os_abs_data_buf(serv_ptr->session->phdl,
							args->aad,
							args->aad_size,
							DATA_BUF_IS_INPUT);
		cmd.aad_size = args->aad_size;
		cmd.rsv = 0;
		cmd.ae_algo = args->ae_algo;
		cmd.flags = args->flags;
		cmd.input_address = (uint32_t)seco_os_abs_data_buf(serv_ptr->session->phdl,
							args->input,
							args->input_size,
							DATA_BUF_IS_INPUT);
		cmd.output_address = (uint32_t)seco_os_abs_data_buf(serv_ptr->session->phdl,
							args->output,
							args->output_size,
							0u);
		cmd.input_length = args->input_size;
		cmd.output_length = args->output_size;
		cmd.crc = seco_compute_msg_crc((uint32_t*)&cmd,
				(uint32_t)(sizeof(cmd) - sizeof(uint32_t)));

		/* Send the message to Seco. */
		err = seco_send_msg_and_get_resp(serv_ptr->session->phdl,
			(uint32_t *)&cmd,
			(uint32_t)sizeof(struct sab_cmd_auth_enc_msg),
			(uint32_t *)&rsp,
			(uint32_t)sizeof(struct sab_cmd_auth_enc_rsp));
		if (err != 0) {
			break;
		}

		err = sab_rating_to_hsm_err(rsp.rsp_code);

	} while (false);

	return err;
}
