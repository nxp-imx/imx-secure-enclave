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
