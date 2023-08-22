// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <string.h>

#include "hsm_api.h"

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"

#include "sab_common_err.h"
#include "sab_msg_def.h"
#include "sab_messaging.h"
#include "sab_process_msg.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

struct sab_cmd_butterfly_key_exp_msg {
	struct sab_mu_hdr hdr;
	uint32_t key_management_handle;
	uint32_t key_identifier;
	uint32_t expansion_function_value_addr;
	uint32_t hash_value_addr;
	uint32_t pr_reconstruction_value_addr;
	uint8_t expansion_function_value_size;
	uint8_t hash_value_size;
	uint8_t pr_reconstruction_value_size;
	uint8_t flags;
	uint32_t dest_key_identifier;
	uint32_t output_address;
	uint16_t output_size;
	uint8_t key_type;
	uint8_t rsv;
	uint16_t key_group;
	uint16_t key_info;
	uint32_t crc;
};

struct sab_cmd_butterfly_key_exp_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
	uint32_t dest_key_identifier;
};

struct sab_import_pub_key_msg {
	struct sab_mu_hdr hdr;
	uint32_t sig_ver_hdl;
	uint32_t key_addr;
	uint16_t key_size;
	uint8_t key_type;
	uint8_t flags;
};

struct sab_import_pub_key_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
	uint32_t key_ref;
};

struct sab_public_key_reconstruct_msg {
	struct sab_mu_hdr hdr;
	uint32_t sesssion_handle;
	uint32_t pu_address_ext;
	uint32_t pu_address;
	uint32_t hash_address_ext;
	uint32_t hash_address;
	uint32_t ca_key_address_ext;
	uint32_t ca_key_address;
	uint32_t out_key_address_ext;
	uint32_t out_key_address;
	uint16_t pu_size;
	uint16_t hash_size;
	uint16_t ca_key_size;
	uint16_t out_key_size;
	uint8_t key_type;
	uint8_t flags;
	uint16_t rsv;
	uint32_t crc;
};

struct sab_public_key_reconstruct_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
};

struct sab_public_key_decompression_msg {
	struct sab_mu_hdr hdr;
	uint32_t sesssion_handle;
	uint32_t input_address_ext;
	uint32_t input_address;
	uint32_t output_address_ext;
	uint32_t output_address;
	uint16_t input_size;
	uint16_t out_size;
	uint8_t key_type;
	uint8_t flags;
	uint16_t rsv;
	uint32_t crc;
};

struct sab_public_key_decompression_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
};

struct sab_root_kek_export_msg {
	struct sab_mu_hdr hdr;
	uint32_t session_handle;
	uint32_t root_kek_address_ext;
	uint32_t root_kek_address;
	uint8_t root_kek_size;
	uint8_t flags;
	uint16_t reserved;
	uint32_t crc;
};

struct sab_root_kek_export_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
};

struct sab_cmd_tls_finish_msg {
	struct sab_mu_hdr hdr;
	uint32_t        key_management_handle;
	uint32_t        key_identifier;
	uint32_t        handshake_hash_input_addr;
	uint32_t        verify_data_output_addr;
	uint16_t        handshake_hash_input_size;
	uint16_t        verify_data_output_size;
	uint8_t         flags;
	uint8_t         hash_algorithm;
	uint16_t        reserved;
	uint32_t        crc;
};

struct sab_cmd_tls_finish_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
};

struct sab_key_generic_crypto_srv_open_msg {
	struct sab_mu_hdr header;
	uint32_t session_handle;
	uint32_t input_address_ext;
	uint32_t output_address_ext;
	uint8_t flags;
	uint8_t rsv[3];
	uint32_t crc;
};

struct sab_key_generic_crypto_srv_open_rsp {
	struct sab_mu_hdr header;
	uint32_t rsp_code;
	uint32_t key_generic_crypto_srv_handle;
};

struct sab_key_generic_crypto_srv_close_msg {
	struct sab_mu_hdr header;
	uint32_t key_generic_crypto_srv_handle;
};

struct sab_key_generic_crypto_srv_close_rsp {
	struct sab_mu_hdr header;
	uint32_t rsp_code;
};

struct sab_key_generic_crypto_srv_msg {
	struct sab_mu_hdr header;
	uint32_t key_generic_crypto_srv_handle;
	uint32_t key_address;
	uint32_t iv_address;
	uint16_t iv_size;
	uint8_t key_size;
	uint8_t crypto_algo;
	uint32_t aad_address;
	uint16_t aad_size;
	uint8_t tag_size;
	uint8_t flags;
	uint32_t input_address;
	uint32_t output_address;
	uint32_t input_length;
	uint32_t output_length;
	uint32_t rsv;
	uint32_t crc;
};

struct sab_key_generic_crypto_srv_rsp {
	struct sab_mu_hdr header;
	uint32_t rsp_code;
};

hsm_err_t hsm_butterfly_key_expansion(hsm_hdl_t key_management_hdl,
				      op_butt_key_exp_args_t *args)
{
	struct sab_cmd_butterfly_key_exp_msg cmd;
	struct sab_cmd_butterfly_key_exp_rsp rsp;
	uint32_t cmd_msg_sz = sizeof(struct sab_cmd_butterfly_key_exp_msg);
	uint32_t rsp_msg_sz = sizeof(struct sab_cmd_butterfly_key_exp_rsp);
	int32_t error;
	struct hsm_service_hdl_s *serv_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;

	do {
		if (!args || !(args->dest_key_identifier))
			break;

		serv_ptr = service_hdl_to_ptr(key_management_hdl);
		if (!serv_ptr) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		/* Send the keys store open command to platform. */
		plat_fill_cmd_msg_hdr(&cmd.hdr,
				      SAB_BUT_KEY_EXP_REQ,
				      cmd_msg_sz,
				      serv_ptr->session->mu_type);

		cmd.key_management_handle = key_management_hdl;
		cmd.key_identifier = args->key_identifier;

		set_phy_addr_to_words(&cmd.expansion_function_value_addr,
				      0u,
				      plat_os_abs_data_buf(serv_ptr->session->phdl,
							   args->expansion_function_value,
							   args->expansion_function_value_size,
							   DATA_BUF_IS_INPUT));
		set_phy_addr_to_words(&cmd.hash_value_addr,
				      0u,
				      plat_os_abs_data_buf(serv_ptr->session->phdl,
							   args->hash_value,
							   args->hash_value_size,
							   DATA_BUF_IS_INPUT));

		set_phy_addr_to_words(&cmd.pr_reconstruction_value_addr,
				      0u,
				      plat_os_abs_data_buf(serv_ptr->session->phdl,
							   args->pr_reconstruction_value,
							   args->pr_reconstruction_value_size,
							   DATA_BUF_IS_INPUT));

		cmd.expansion_function_value_size = args->expansion_function_value_size;
		cmd.hash_value_size = args->hash_value_size;
		cmd.pr_reconstruction_value_size = args->pr_reconstruction_value_size;
		cmd.flags = args->flags;
		cmd.dest_key_identifier = *args->dest_key_identifier;
		set_phy_addr_to_words(&cmd.output_address,
				      0u,
				      plat_os_abs_data_buf(serv_ptr->session->phdl,
							   args->output,
							   args->output_size,
							   0u));
		cmd.output_size = args->output_size;
		cmd.key_type = args->key_type;
		cmd.rsv = 0u;
		cmd.key_group = args->key_group;
		cmd.key_info = args->key_info;
		cmd.crc = 0u;
		cmd.crc = plat_compute_msg_crc((uint32_t *)&cmd,
					       (uint32_t)(sizeof(cmd) - sizeof(uint32_t)));

		/* Send the message to platform. */
		error = plat_send_msg_and_get_resp(serv_ptr->session->phdl,
						   (uint32_t *)&cmd,
						   cmd_msg_sz,
						   (uint32_t *)&rsp,
						   rsp_msg_sz);
		if (error != 0)
			break;

		sab_err_map(SAB_MSG, SAB_BUT_KEY_EXP_REQ, rsp.rsp_code);

		err = sab_rating_to_hsm_err(rsp.rsp_code);
		if (err == HSM_NO_ERROR &&
		    ((cmd.flags & HSM_OP_BUTTERFLY_KEY_FLAGS_CREATE) ==
		     HSM_OP_BUTTERFLY_KEY_FLAGS_CREATE)) {
			*args->dest_key_identifier = rsp.dest_key_identifier;
		}

	} while (false);

	return err;
}

hsm_err_t hsm_import_public_key(hsm_hdl_t signature_ver_hdl,
				op_import_public_key_args_t *args,
				uint32_t *key_ref)
{
	struct sab_import_pub_key_msg cmd;
	struct sab_import_pub_key_rsp rsp;
	uint32_t cmd_msg_sz = sizeof(struct sab_import_pub_key_msg);
	uint32_t rsp_msg_sz = sizeof(struct sab_import_pub_key_rsp);
	int32_t error;
	struct hsm_service_hdl_s *serv_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;

	do {
		if (!args || !key_ref)
			break;

		serv_ptr = service_hdl_to_ptr(signature_ver_hdl);
		if (!serv_ptr) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		/* Send the keys store open command to platform. */
		plat_fill_cmd_msg_hdr(&cmd.hdr,
				      SAB_IMPORT_PUB_KEY,
				      cmd_msg_sz,
				      serv_ptr->session->mu_type);
		cmd.sig_ver_hdl = signature_ver_hdl;
		set_phy_addr_to_words(&cmd.key_addr,
				      0u,
				      plat_os_abs_data_buf(serv_ptr->session->phdl,
							   args->key,
							   args->key_size,
							   DATA_BUF_IS_INPUT));
		cmd.key_size = args->key_size;
		cmd.key_type = args->key_type;
		cmd.flags = args->flags;

		/* Send the message to platform. */
		error = plat_send_msg_and_get_resp(serv_ptr->session->phdl,
						   (uint32_t *)&cmd,
						   cmd_msg_sz,
						   (uint32_t *)&rsp,
						   rsp_msg_sz);

		if (error != 0)
			break;

		sab_err_map(SAB_MSG, SAB_IMPORT_PUB_KEY, rsp.rsp_code);

		err = sab_rating_to_hsm_err(rsp.rsp_code);
		*key_ref = rsp.key_ref;
	} while (false);

	return err;
}

hsm_err_t hsm_pub_key_reconstruction(hsm_hdl_t session_hdl,
				     op_pub_key_rec_args_t *args)
{
	struct sab_public_key_reconstruct_msg cmd;
	struct sab_public_key_reconstruct_rsp rsp;
	uint32_t cmd_msg_sz = sizeof(struct sab_public_key_reconstruct_msg);
	uint32_t rsp_msg_sz = sizeof(struct sab_public_key_reconstruct_rsp);
	int32_t error;
	struct hsm_session_hdl_s *sess_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;

	do {
		if (!args || !session_hdl)
			break;

		sess_ptr = session_hdl_to_ptr(session_hdl);
		if (!sess_ptr) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		/* Send the keys store open command to platform. */
		plat_fill_cmd_msg_hdr(&cmd.hdr,
				      SAB_PUB_KEY_RECONSTRUCTION_REQ,
				      cmd_msg_sz,
				      sess_ptr->mu_type);

		cmd.sesssion_handle = session_hdl;
		cmd.pu_address_ext = 0u;
		set_phy_addr_to_words(&cmd.pu_address,
				      0u,
				      plat_os_abs_data_buf(sess_ptr->phdl,
							   args->pub_rec,
							   args->pub_rec_size,
							   DATA_BUF_IS_INPUT));
		cmd.hash_address_ext = 0u;
		set_phy_addr_to_words(&cmd.hash_address,
				      0u,
				      plat_os_abs_data_buf(sess_ptr->phdl,
							   args->hash,
							   args->hash_size,
							   DATA_BUF_IS_INPUT));
		cmd.ca_key_address_ext = 0u;
		set_phy_addr_to_words(&cmd.ca_key_address,
				      0u,
				      plat_os_abs_data_buf(sess_ptr->phdl,
							   args->ca_key,
							   args->ca_key_size,
							   DATA_BUF_IS_INPUT));
		cmd.out_key_address_ext = 0u;
		set_phy_addr_to_words(&cmd.out_key_address,
				      0u,
				      plat_os_abs_data_buf(sess_ptr->phdl,
							   args->out_key,
							   args->out_key_size,
							   0u));
		cmd.pu_size = args->pub_rec_size;
		cmd.hash_size = args->hash_size;
		cmd.ca_key_size = args->ca_key_size;
		cmd.out_key_size = args->out_key_size;
		cmd.key_type = args->key_type;
		cmd.flags = args->flags;
		cmd.rsv = 0u;
		cmd.crc = 0u;
		cmd.crc = plat_compute_msg_crc((uint32_t *)&cmd,
					       (uint32_t)(sizeof(cmd) - sizeof(uint32_t)));

		/* Send the message to platform. */
		error = plat_send_msg_and_get_resp(sess_ptr->phdl,
						   (uint32_t *)&cmd,
						   cmd_msg_sz,
						   (uint32_t *)&rsp,
						   rsp_msg_sz);
		if (error != 0)
			break;

		sab_err_map(SAB_MSG, SAB_PUB_KEY_RECONSTRUCTION_REQ, rsp.rsp_code);

		err = sab_rating_to_hsm_err(rsp.rsp_code);
	} while (false);

	return err;
}

hsm_err_t hsm_pub_key_decompression(hsm_hdl_t session_hdl,
				    op_pub_key_dec_args_t *args)
{
	struct sab_public_key_decompression_msg cmd;
	struct sab_public_key_decompression_rsp rsp;
	uint32_t cmd_msg_sz = sizeof(struct sab_public_key_decompression_msg);
	uint32_t rsp_msg_sz = sizeof(struct sab_public_key_decompression_rsp);
	int32_t error;
	struct hsm_session_hdl_s *sess_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;

	do {
		if (!args || !session_hdl)
			break;

		sess_ptr = session_hdl_to_ptr(session_hdl);
		if (!sess_ptr) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		/* Send the keys store open command to platform. */
		plat_fill_cmd_msg_hdr(&cmd.hdr,
				      SAB_PUB_KEY_DECOMPRESSION_REQ,
				      cmd_msg_sz,
				      sess_ptr->mu_type);
		cmd.sesssion_handle = session_hdl;
		cmd.input_address_ext = 0u;
		set_phy_addr_to_words(&cmd.input_address,
				      0u,
				      plat_os_abs_data_buf(sess_ptr->phdl,
							   args->key,
							   args->key_size,
							   DATA_BUF_IS_INPUT));
		cmd.output_address_ext = 0u;
		set_phy_addr_to_words(&cmd.output_address,
				      0u,
				      plat_os_abs_data_buf(sess_ptr->phdl,
							   args->out_key,
							   args->out_key_size,
							   0u));
		cmd.input_size = args->key_size;
		cmd.out_size = args->out_key_size;
		cmd.key_type = args->key_type;
		cmd.flags = args->flags;
		cmd.rsv = 0u;
		cmd.crc = 0u;
		cmd.crc = plat_compute_msg_crc((uint32_t *)&cmd,
					       (uint32_t)(sizeof(cmd) - sizeof(uint32_t)));

		/* Send the message to platform. */
		error = plat_send_msg_and_get_resp(sess_ptr->phdl,
						   (uint32_t *)&cmd,
						   cmd_msg_sz,
						   (uint32_t *)&rsp,
						   rsp_msg_sz);
		if (error != 0)
			break;

		sab_err_map(SAB_MSG, SAB_PUB_KEY_DECOMPRESSION_REQ, rsp.rsp_code);

		err = sab_rating_to_hsm_err(rsp.rsp_code);
	} while (false);

	return err;
}

hsm_err_t hsm_export_root_key_encryption_key(hsm_hdl_t session_hdl,
					     op_export_root_kek_args_t *args)
{
	struct sab_root_kek_export_msg cmd;
	struct sab_root_kek_export_rsp rsp;
	uint32_t cmd_msg_sz = sizeof(struct sab_root_kek_export_msg);
	uint32_t rsp_msg_sz = sizeof(struct sab_root_kek_export_rsp);
	struct hsm_session_hdl_s *sess_ptr;
	int32_t error;
	hsm_err_t err = HSM_GENERAL_ERROR;

	do {
		if (!args || !session_hdl)
			break;

		sess_ptr = session_hdl_to_ptr(session_hdl);
		if (!sess_ptr) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		/* Send the signed message to platform if provided here. */
		if (args->signed_message) {
			(void)plat_os_abs_send_signed_message(sess_ptr->phdl,
							      args->signed_message,
							      args->signed_msg_size);
		}

		plat_fill_cmd_msg_hdr(&cmd.hdr,
				      SAB_ROOT_KEK_EXPORT_REQ,
				      cmd_msg_sz,
				      sess_ptr->mu_type);
		cmd.session_handle = session_hdl;
		cmd.root_kek_address_ext = 0;
		set_phy_addr_to_words(&cmd.root_kek_address,
				      0u,
				      plat_os_abs_data_buf(sess_ptr->phdl,
							   args->out_root_kek,
							   args->root_kek_size,
							   0u));
		cmd.flags = args->flags;
		cmd.root_kek_size = args->root_kek_size;
		cmd.reserved = 0u;
		cmd.crc = 0;
		cmd.crc = plat_compute_msg_crc((uint32_t *)&cmd,
					       (uint32_t)(sizeof(cmd) - sizeof(uint32_t)));

		error = plat_send_msg_and_get_resp(sess_ptr->phdl,
						   (uint32_t *)&cmd,
						   cmd_msg_sz,
						   (uint32_t *)&rsp,
						   rsp_msg_sz);

		if (error != 0)
			break;

		sab_err_map(SAB_MSG, SAB_ROOT_KEK_EXPORT_REQ, rsp.rsp_code);

		err = sab_rating_to_hsm_err(rsp.rsp_code);

	} while (false);

	return err;
}

hsm_err_t hsm_tls_finish(hsm_hdl_t key_management_hdl, op_tls_finish_args_t *args)
{
	struct sab_cmd_tls_finish_msg cmd;
	struct sab_cmd_tls_finish_rsp rsp;
	uint32_t cmd_msg_sz = sizeof(struct sab_cmd_tls_finish_msg);
	uint32_t rsp_msg_sz = sizeof(struct sab_cmd_tls_finish_rsp);
	int32_t error;
	struct hsm_service_hdl_s *serv_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;

	do {
		if (!args)
			break;

		serv_ptr = service_hdl_to_ptr(key_management_hdl);
		if (!serv_ptr) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		/* Prepare the plat commmand */
		plat_fill_cmd_msg_hdr(&cmd.hdr,
				      SAB_TLS_FINISH_REQ,
				      cmd_msg_sz,
				      serv_ptr->session->mu_type);

		cmd.key_management_handle = key_management_hdl;
		cmd.key_identifier = args->key_identifier;
		set_phy_addr_to_words(&cmd.handshake_hash_input_addr,
				      0u,
				      plat_os_abs_data_buf(serv_ptr->session->phdl,
							   args->handshake_hash_input,
							   args->handshake_hash_input_size,
							   DATA_BUF_IS_INPUT));
		set_phy_addr_to_words(&cmd.verify_data_output_addr,
				      0u,
				      plat_os_abs_data_buf(serv_ptr->session->phdl,
							   args->verify_data_output,
							   args->verify_data_output_size,
							   0u));
		cmd.handshake_hash_input_size = args->handshake_hash_input_size;
		cmd.verify_data_output_size = args->verify_data_output_size;
		cmd.flags = args->flags;
		cmd.hash_algorithm = args->hash_algorithm;
		cmd.reserved = 0;
		cmd.crc = 0u;
		cmd.crc = plat_compute_msg_crc((uint32_t *)&cmd,
					       (uint32_t)(sizeof(cmd) - sizeof(uint32_t)));

		/* Send the message to platform. */
		error = plat_send_msg_and_get_resp(serv_ptr->session->phdl,
						   (uint32_t *)&cmd,
						   cmd_msg_sz,
						   (uint32_t *)&rsp,
						   rsp_msg_sz);
		if (error != 0)
			break;

		sab_err_map(SAB_MSG, SAB_TLS_FINISH_REQ, rsp.rsp_code);

		err = sab_rating_to_hsm_err(rsp.rsp_code);

	} while (false);

	return err;
}

hsm_err_t hsm_open_key_generic_crypto_service(hsm_hdl_t session_hdl,
					      open_svc_key_generic_crypto_args_t *args,
					      hsm_hdl_t *key_generic_crypto_hdl)
{
	struct sab_key_generic_crypto_srv_open_msg cmd;
	struct sab_key_generic_crypto_srv_open_rsp rsp;
	uint32_t cmd_msg_sz = sizeof(struct sab_key_generic_crypto_srv_open_msg);
	uint32_t rsp_msg_sz = sizeof(struct sab_key_generic_crypto_srv_open_rsp);
	struct hsm_session_hdl_s *sess_ptr;
	struct hsm_service_hdl_s *serv_ptr;
	int32_t error;
	hsm_err_t err = HSM_GENERAL_ERROR;

	do {
		if (!args || !key_generic_crypto_hdl)
			break;

		sess_ptr = session_hdl_to_ptr(session_hdl);
		if (!sess_ptr) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		serv_ptr = add_service(sess_ptr);
		if (!serv_ptr)
			break;

		plat_fill_cmd_msg_hdr(&cmd.header,
				      SAB_KEY_GENERIC_CRYPTO_SRV_OPEN_REQ,
				      cmd_msg_sz,
				      serv_ptr->session->mu_type);

		cmd.session_handle = session_hdl;
		cmd.input_address_ext = 0u;
		cmd.output_address_ext = 0u;
		cmd.flags = args->flags;
		cmd.rsv[0] = 0u;
		cmd.rsv[1] = 0u;
		cmd.rsv[2] = 0u;
		cmd.crc = 0u;
		cmd.crc = plat_compute_msg_crc((uint32_t *)&cmd,
					       (uint32_t)(sizeof(cmd) - sizeof(uint32_t)));

		error = plat_send_msg_and_get_resp(sess_ptr->phdl,
						   (uint32_t *)&cmd,
						   cmd_msg_sz,
						   (uint32_t *)&rsp,
						   rsp_msg_sz);
		if (error != 0) {
			delete_service(serv_ptr);
			break;
		}

		sab_err_map(SAB_MSG, SAB_KEY_GENERIC_CRYPTO_SRV_OPEN_REQ, rsp.rsp_code);

		err = sab_rating_to_hsm_err(rsp.rsp_code);
		if (err != HSM_NO_ERROR) {
			delete_service(serv_ptr);
			break;
		}

		serv_ptr->service_hdl = rsp.key_generic_crypto_srv_handle;
		*key_generic_crypto_hdl = rsp.key_generic_crypto_srv_handle;
	} while (false);

	return err;
}

hsm_err_t hsm_close_key_generic_crypto_service(hsm_hdl_t key_generic_crypto_hdl)
{
	struct sab_key_generic_crypto_srv_close_msg cmd;
	struct sab_key_generic_crypto_srv_close_rsp rsp;
	uint32_t cmd_msg_sz = sizeof(struct sab_key_generic_crypto_srv_close_msg);
	uint32_t rsp_msg_sz = sizeof(struct sab_key_generic_crypto_srv_close_rsp);
	struct hsm_service_hdl_s *serv_ptr;
	int32_t error;
	hsm_err_t err = HSM_GENERAL_ERROR;

	do {
		if (!key_generic_crypto_hdl)
			break;

		serv_ptr = service_hdl_to_ptr(key_generic_crypto_hdl);
		if (!serv_ptr) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		plat_fill_cmd_msg_hdr(&cmd.header,
				      SAB_KEY_GENERIC_CRYPTO_SRV_CLOSE_REQ,
				      cmd_msg_sz,
				      serv_ptr->session->mu_type);
		cmd.key_generic_crypto_srv_handle = key_generic_crypto_hdl;

		error = plat_send_msg_and_get_resp(serv_ptr->session->phdl,
						   (uint32_t *)&cmd,
						   cmd_msg_sz,
						   (uint32_t *)&rsp,
						   rsp_msg_sz);
		if (error == 0) {
			sab_err_map(SAB_MSG,
				    SAB_KEY_GENERIC_CRYPTO_SRV_CLOSE_REQ,
				    rsp.rsp_code);
			err = sab_rating_to_hsm_err(rsp.rsp_code);
		}
		delete_service(serv_ptr);
	} while (false);

	return err;
}

hsm_err_t hsm_key_generic_crypto(hsm_hdl_t key_generic_crypto_hdl,
				 op_key_generic_crypto_args_t *args)
{
	struct sab_key_generic_crypto_srv_msg cmd;
	struct sab_key_generic_crypto_srv_rsp rsp;
	uint32_t cmd_msg_sz = sizeof(struct sab_key_generic_crypto_srv_msg);
	uint32_t rsp_msg_sz = sizeof(struct sab_key_generic_crypto_srv_rsp);
	struct hsm_service_hdl_s *serv_ptr;
	hsm_err_t err = HSM_GENERAL_ERROR;
	int32_t error;

	do {
		if (!args)
			break;

		serv_ptr = service_hdl_to_ptr(key_generic_crypto_hdl);
		if (!serv_ptr) {
			err = HSM_UNKNOWN_HANDLE;
			break;
		}

		/* Fill the authenticated encryption command */
		plat_fill_cmd_msg_hdr(&cmd.header,
				      SAB_KEY_GENERIC_CRYPTO_SRV_REQ,
				      cmd_msg_sz,
				      serv_ptr->session->mu_type);

		cmd.key_generic_crypto_srv_handle = key_generic_crypto_hdl;
		cmd.key_size = args->key_size;
		set_phy_addr_to_words(&cmd.key_address,
				      0u,
				      plat_os_abs_data_buf(serv_ptr->session->phdl,
							   args->key,
							   args->key_size,
							   DATA_BUF_IS_INPUT));
		if (args->iv_size != 0) {
			set_phy_addr_to_words(&cmd.iv_address,
					      0u,
					      plat_os_abs_data_buf(serv_ptr->session->phdl,
								   args->iv,
								   args->iv_size,
								   DATA_BUF_IS_INPUT));
		} else {
			cmd.iv_address = 0;
		}

		cmd.iv_size = args->iv_size;
		set_phy_addr_to_words(&cmd.aad_address,
				      0u,
				      plat_os_abs_data_buf(serv_ptr->session->phdl,
							   args->aad,
							   args->aad_size,
							   DATA_BUF_IS_INPUT));
		cmd.aad_size = args->aad_size;
		cmd.rsv = 0;
		cmd.crypto_algo = args->crypto_algo;
		cmd.flags = args->flags;
		cmd.tag_size = args->tag_size;
		set_phy_addr_to_words(&cmd.input_address,
				      0u,
				      plat_os_abs_data_buf(serv_ptr->session->phdl,
							   args->input,
							   args->input_size,
							   DATA_BUF_IS_INPUT));
		set_phy_addr_to_words(&cmd.output_address,
				      0u,
				      plat_os_abs_data_buf(serv_ptr->session->phdl,
							   args->output,
							   args->output_size,
							   0u));
		cmd.input_length = args->input_size;
		cmd.output_length = args->output_size;
		cmd.rsv = args->reserved;
		cmd.crc = 0u;
		cmd.crc = plat_compute_msg_crc((uint32_t *)&cmd,
					       (uint32_t)(sizeof(cmd) - sizeof(uint32_t)));

		/* Send the message to platform. */
		error = plat_send_msg_and_get_resp(serv_ptr->session->phdl,
						   (uint32_t *)&cmd,
						   cmd_msg_sz,
						   (uint32_t *)&rsp,
						   rsp_msg_sz);
		if (error != 0)
			break;

		sab_err_map(SAB_MSG, SAB_KEY_GENERIC_CRYPTO_SRV_REQ, rsp.rsp_code);

		err = sab_rating_to_hsm_err(rsp.rsp_code);

	} while (false);

	return err;
}
