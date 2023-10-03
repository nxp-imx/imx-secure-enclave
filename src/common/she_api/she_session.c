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
	struct she_session_hdl_s *hdl;
	she_err_t err = SHE_GENERAL_ERROR;
	uint32_t lib_err;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	if (!session_hdl)
		return err;

	hdl = she_session_hdl_to_ptr(session_hdl);
	if (!hdl)
		return err;

	lib_err = process_sab_msg(hdl->phdl,
				  hdl->mu_type,
				  SAB_SESSION_CLOSE_REQ,
				  MT_SAB_SESSION,
				  hdl->session_hdl,
				  NULL, &rsp_code);

	err = lib_err_to_she_err(lib_err);

	if (err != SHE_NO_ERROR)
		return err;

	err = sab_rating_to_she_err(rsp_code);
	if (err != SHE_NO_ERROR) {
		se_err("SHE RSP Error: SAB_SESSION_CLOSE_REQ [0x%x].\n", err);
		return err;
	}

	plat_os_abs_close_session(hdl->phdl);

	delete_she_session(hdl);

	return err;
}

she_err_t open_session(open_session_args_t *args,
		       struct she_session_hdl_s **hdl,
		       uint32_t mu_type)
{
	struct plat_mu_params mu_params = {'\0'};
	struct she_session_hdl_s *thdl = NULL;
	she_err_t err = SHE_GENERAL_ERROR;
	uint32_t lib_err;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	thdl = add_she_session();
	if (!thdl)
		return err;

	plat_os_abs_memset((uint8_t *)thdl, 0u,
			   (uint32_t)sizeof(struct she_session_hdl_s));

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
	args->session_priority = SHE_OPEN_SESSION_PRIORITY_LOW;
	args->operating_mode = 0U;

	/* Open the SHE session on Platform's side */
	lib_err = process_sab_msg(thdl->phdl,
				  thdl->mu_type,
				  SAB_SESSION_OPEN_REQ,
				  MT_SAB_SESSION,
				  thdl->session_hdl,
				  args, &rsp_code);

	err = lib_err_to_she_err(lib_err);

	if (err != SHE_NO_ERROR)
		return err;

	err = sab_rating_to_she_err(rsp_code);
	if (err != SHE_NO_ERROR) {
		se_err("SHE RSP Error: SAB_SESSION_OPEN_REQ [0x%x].\n", err);
		return err;
	}

	thdl->session_hdl = args->session_hdl;

	*hdl = thdl;

	return err;
}

she_err_t she_open_session(open_session_args_t *args, she_hdl_t *session_hdl)
{
	struct she_session_hdl_s *hdl = NULL;
	she_err_t err = SHE_GENERAL_ERROR;
	uint32_t sab_err, ret;
	op_get_info_args_t info_args = {'\0'};
	op_shared_buf_args_t buf_args = {'\0'};
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	do {
		if (!args || !session_hdl)
			break;

		err = open_session(args, &hdl, MU_CHANNEL_PLAT_SHE);
		if (err != SHE_NO_ERROR)
			break;

		err = she_get_info(hdl->session_hdl, &info_args);
		if (err != SHE_NO_ERROR) {
			se_err("SHE Error: Failed to get SHE info 0x%x\n", err);
			break;
		}
		printf("info_args.fips_mode 0x%x\n", info_args.fips_mode);

		if (info_args.fips_mode & 0x01) {
			she_close_session(hdl->session_hdl);

			err = open_session(args, &hdl, MU_CHANNEL_V2X_SHE);
			if (err != SHE_NO_ERROR)
				break;

			she_v2x_mu = 1;
		}
		printf("she_v2x_mu 0x%x\n", she_v2x_mu);

		*session_hdl = hdl->session_hdl;

		se_print("open session : 0x%x : 0x%x\n",
			 hdl->session_hdl, *session_hdl);

		if (!she_v2x_mu) {
			/* Get a SECURE RAM partition to be used as shared buffer */
			sab_err = process_sab_msg(hdl->phdl,
						  hdl->mu_type,
						  SAB_SHARED_BUF_REQ,
						  MT_SAB_SHARED_BUF,
						  hdl->session_hdl,
						  &buf_args, &rsp_code);

			err = sab_rating_to_she_err(sab_err);
			if (err != SHE_NO_ERROR) {
				se_err("SHE Error: SAB_SHARED_BUF_REQ [0x%x].\n", err);
				break;
			}

			err = sab_rating_to_she_err(rsp_code);
			if (err != SHE_NO_ERROR) {
				se_err("SHE RSP Error: SAB_SHARED_BUF_REQ [0x%x].\n",
				       err);
				break;
			}
			se_print("Get shared buffer 0x%x : 0x%x\n",
				 buf_args.shared_buf_offset, buf_args.shared_buf_size);
			/* Configure the shared buffer. */
			ret = plat_os_abs_configure_shared_buf_v2
					(hdl->phdl,
					 buf_args.shared_buf_offset,
					 buf_args.shared_buf_size);

			err = plat_err_to_she_err(SAB_SHARED_BUF_REQ,
						  ret,
						  SHE_RESPONSE);
			if (err != SHE_NO_ERROR)
				break;

		}
	} while (false);

	if (err != SHE_NO_ERROR) {
		if (hdl) {
			if (hdl->session_hdl != 0u) {
				(void)she_close_session(hdl->session_hdl);
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

uint32_t she_get_last_rating_code(she_hdl_t session_hdl)
{
	struct she_session_hdl_s *sess_ptr;

	sess_ptr = she_session_hdl_to_ptr(session_hdl);
	if (!sess_ptr) {
		se_err("session pointer not found\n");
		return SHE_GENERAL_ERROR;
	}

	return sess_ptr->last_rating;
}
