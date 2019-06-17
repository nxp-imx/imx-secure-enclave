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
	}

	return hsm_err;
}

hsm_err_t hsm_close_session(uint32_t session_hdl)
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

		/* Get a SECURE RAM partition to be used as shared buffer */
		sab_err = sab_get_shared_buffer(s_ptr->phdl,
						s_ptr->session_hdl);
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
