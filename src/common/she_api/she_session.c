// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <stdbool.h>
#include <stdio.h>

#include "she_api.h"
#include "sab_process_msg.h"

uint8_t she_v2x_mu;

she_err_t she_close_session(she_hdl_t session_hdl)
{
	struct she_hdl_s *hdl;
	she_err_t err = SHE_GENERAL_ERROR;
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

she_err_t open_session(open_session_args_t *args, struct she_hdl_s **hdl, uint32_t mu_type)
{
	struct plat_mu_params mu_params = {'\0'};
	struct she_hdl_s *thdl = NULL;
	she_err_t err = SHE_GENERAL_ERROR;
	uint32_t sab_err;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	thdl = add_she_session();
	if (!thdl)
		return err;

	plat_os_abs_memset((uint8_t *)thdl, 0u, (uint32_t)sizeof(struct she_hdl_s));

	/* Open the SHE session on the MU */
	thdl->mu_type = mu_type;
	thdl->phdl = plat_os_abs_open_mu_channel(thdl->mu_type, &mu_params);
	if (!thdl->phdl)
		return err;

#ifndef PSA_COMPLIANT
	args->mu_id = mu_params.mu_id;
	args->tz = mu_params.tz;
	args->did = mu_params.did;
#endif
	args->interrupt_idx = mu_params.interrupt_idx;
	args->session_priority = SAB_OPEN_SESSION_PRIORITY_LOW;
	args->operating_mode = 0U;

	/* Open the SHE session on Platform's side */
	sab_err = process_sab_msg(thdl->phdl,
				  thdl->mu_type,
				  SAB_SESSION_OPEN_REQ,
				  MT_SAB_SESSION,
				  thdl->session_handle,
				  args, &rsp_code);

	err = sab_rating_to_she_err(sab_err);

	if (err != SHE_NO_ERROR) {
		se_err("SHE Error: SAB_SESSION_OPEN_REQ [0x%x].\n", err);
		return err;
	}

	err = sab_rating_to_she_err(rsp_code);
	if (err != SHE_NO_ERROR) {
		se_err("SHE RSP Error: SAB_SESSION_OPEN_REQ [0x%x].\n", err);
		return err;
	}

	thdl->session_handle = args->session_hdl;

	*hdl = thdl;

	return err;
}

she_err_t she_open_session(open_session_args_t *args, she_hdl_t *session_hdl)
{
	struct she_hdl_s *hdl = NULL;
	she_err_t err = SHE_GENERAL_ERROR;
	uint32_t sab_err;
	op_get_info_args_t info_args = {'\0'};

	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	do {
		if (!args || !session_hdl)
			break;

		err = open_session(args, &hdl, MU_CHANNEL_PLAT_SHE);
		if (err != SHE_NO_ERROR)
			break;

		sab_err = process_sab_msg(hdl->phdl,
					  hdl->mu_type,
					  SAB_GET_INFO_REQ,
					  MT_SAB_GET_INFO,
					  hdl->session_handle,
					  &info_args, &rsp_code);

		err = sab_rating_to_she_err(sab_err);

		if (err != SHE_NO_ERROR) {
			se_err("SHE Error: SAB_GET_INFO_REQ [0x%x].\n", err);
			break;
		}

		err = sab_rating_to_she_err(rsp_code);
		if (err != SHE_NO_ERROR) {
			se_err("SHE RSP Error: SAB_GET_INFO_REQ [0x%x].\n", err);
			break;
		}

		if (info_args.fips_mode & 0x01) {
			she_close_session(hdl->session_handle);

			err = open_session(args, &hdl, MU_CHANNEL_V2X_SHE);
			if (err != SHE_NO_ERROR)
				break;

			she_v2x_mu = 1;

			hdl->session_handle = args->session_hdl;
		}

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
