// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <stdbool.h>
#include <stdio.h>

#include "she_api.h"
#include "sab_process_msg.h"

she_err_t she_close_session(she_hdl_t session_hdl)
{
	struct she_hdl_s *hdl;
	she_err_t err = SHE_UNKNOWN_ERROR;
	uint32_t sab_err;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	if (!session_hdl)
		return err;

	hdl = she_session_hdl_to_ptr(session_hdl);
	if (!hdl)
		return err;

	sab_err = process_sab_msg(hdl->phdl,
				  hdl->mu_type,
				  SAB_SESSION_CLOSE_REQ,
				  MT_SAB_SESSION,
				  hdl->session_handle,
				  NULL, &rsp_code);

	err = sab_rating_to_she_err(sab_err);
	if (err != SHE_NO_ERROR) {
		se_err("SHE Error: SAB_SESSION_CLOSE_REQ [0x%x].\n", err);
		return err;
	}

	err = sab_rating_to_she_err(rsp_code);
	if (err != SHE_NO_ERROR) {
		se_err("SHE RSP Error: SAB_SESSION_CLOSE_REQ [0x%x].\n", err);
		return err;
	}

	plat_os_abs_close_session(hdl->phdl);

	delete_she_session(hdl);

	return err;
}

she_err_t she_open_session(open_session_args_t *args, she_hdl_t *session_hdl)
{
	struct she_hdl_s *hdl = NULL;
	struct plat_mu_params mu_params = {'\0'};
	she_err_t err = SHE_GENERAL_ERROR;
	uint32_t sab_err;

	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	do {
		if (!args || !session_hdl)
			break;

		hdl = add_she_session();
		printf("open session: add_she_session 0x%p\n", hdl);
		if (!hdl)
			break;

		plat_os_abs_memset((uint8_t *)hdl, 0u, (uint32_t)sizeof(struct she_hdl_s));

		/* Open the SHE session on the MU */
		hdl->mu_type = MU_CHANNEL_PLAT_SHE;
		hdl->phdl = plat_os_abs_open_mu_channel(hdl->mu_type, &mu_params);
		if (!hdl->phdl)
			break;

#ifndef PSA_COMPLIANT
		args->mu_id = mu_params.mu_id;
		args->tz = mu_params.tz;
		args->did = mu_params.did;
#endif
		args->interrupt_idx = mu_params.interrupt_idx;
		args->session_priority = SAB_OPEN_SESSION_PRIORITY_LOW;
		args->operating_mode = 0U;

		/* Open the SHE session on Platform's side */
		sab_err = process_sab_msg(hdl->phdl,
					  hdl->mu_type,
					  SAB_SESSION_OPEN_REQ,
					  MT_SAB_SESSION,
					  hdl->session_handle,
					  args, &rsp_code);

		err = sab_rating_to_she_err(sab_err);

		if (err != SHE_NO_ERROR) {
			se_err("SHE Error: SAB_SESSION_OPEN_REQ [0x%x].\n", err);
			break;
		}

		err = sab_rating_to_she_err(rsp_code);
		if (err != SHE_NO_ERROR) {
			se_err("SHE RSP Error: SAB_SESSION_OPEN_REQ [0x%x].\n", err);
			break;
		}

		hdl->session_handle = args->session_hdl;
		*session_hdl = hdl->session_handle;

		printf("open session : 0x%x : 0x%x\n", hdl->session_handle, *session_hdl);
	} while (false);

	if (err != SHE_NO_ERROR) {
		if (hdl) {
			if (hdl->session_handle != 0u) {
				(void)she_close_session(hdl->session_handle);
			} else if (hdl->phdl) {
				plat_os_abs_close_session(hdl->phdl);
				delete_she_session(hdl);
			} else {
				delete_she_session(hdl);
			}
		}
		if (session_hdl)
			*session_hdl = 0u; /* force an invalid value.*/
	}

	return err;
}
