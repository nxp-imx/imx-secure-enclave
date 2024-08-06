// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#include <stdbool.h>
#include <stdio.h>

#include "she_api.h"
#include "sab_process_msg.h"

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

	err = sab_rating_to_she_err(rsp_code, hdl->phdl);
	if (err != SHE_NO_ERROR) {
		se_err("SHE RSP Error: SAB_SESSION_CLOSE_REQ [0x%x].\n", err);
		return err;
	}

	plat_os_abs_close_session(hdl->phdl);

	delete_she_session(hdl);

	return err;
}

static she_err_t get_shared_buff(struct she_session_hdl_s *hdl)
{
	op_shared_buf_args_t buf_args = {'\0'};
	she_err_t err = SHE_GENERAL_ERROR;
	uint32_t lib_err;
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	lib_err = process_sab_msg(hdl->phdl,
				  hdl->mu_type,
				  SAB_SHARED_BUF_REQ,
				  MT_SAB_SHARED_BUF,
				  hdl->session_hdl,
				  &buf_args, &rsp_code);

	err = lib_err_to_she_err(lib_err);
	if (err != SHE_NO_ERROR)
		return err;

	err = sab_rating_to_she_err(rsp_code, hdl->phdl);
	if (err != SHE_NO_ERROR) {
		se_err("SHE RSP Error: SAB_SHARED_BUF_REQ [0x%x].\n", err);
		return err;
	}

	se_print("Get shared buffer 0x%x : 0x%x\n",
		 buf_args.shared_buf_offset, buf_args.shared_buf_size);

	/* Configure the shared buffer. */
	lib_err = plat_os_abs_configure_shared_buf_v2(hdl->phdl,
						      buf_args.shared_buf_offset,
						      buf_args.shared_buf_size);

	err = plat_err_to_she_err(SAB_SHARED_BUF_REQ,
				  lib_err, SHE_RESPONSE);
	if (err != SHE_NO_ERROR)
		return err;

	return err;
}

she_err_t open_session(open_session_args_t *args,
		       struct she_session_hdl_s **hdl)
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
	thdl->phdl = plat_os_abs_open_mu_channel(args->mu_type, &mu_params);
	if (!thdl->phdl)
		return err;

	thdl->mu_type = args->mu_type;
#ifndef PSA_COMPLIANT
	args->mu_id = mu_params.mu_id;
	args->tz = mu_params.tz;
	args->did = mu_params.did;
#endif
	if (!args->interrupt_idx)
		args->interrupt_idx = mu_params.interrupt_idx;
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

	err = sab_rating_to_she_err(rsp_code, thdl->phdl);
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
	uint32_t rsp_code = SAB_NO_MESSAGE_RATING;

	do {
		if (!args || !session_hdl)
			break;

		/*
		 * global information will be populated after opening session
		 * This is a precautionary check and will be executed if more than
		 * open session will be opened.
		 */
		if (is_global_info_populated()) {
			if (se_get_soc_id() == SOC_IMX8DXL) {
				if (se_get_board_type() == IMX8DXL_DL3 &&
				    args->mu_type != V2X_SHE) {
					se_print("Incorrect MU Type %d\n", args->mu_type);
					return err;
				} else if (se_get_board_type() == IMX8DXL_DL1 &&
					   args->mu_type != SHE1) {
					se_print("Incorrect MU Type %d\n", args->mu_type);
					return err;
				} else if (se_get_board_type() == IMX8DXL_DL2) {
					se_print("DL2 board:SHE session can not open\n");
					return err;
				}
			}
		}

		err = open_session(args, &hdl);
		if (err != SHE_NO_ERROR)
			break;

		//populate Global Info structure
		if (err == SHE_NO_ERROR && !is_global_info_populated())
			populate_global_info(args->session_hdl);

		args->session_hdl = hdl->session_hdl;
		*session_hdl = hdl->session_hdl;

		if (se_get_soc_id() == SOC_IMX8DXL &&
		    se_get_board_type() == IMX8DXL_DL1) {
			/* Get a SECURE RAM partition to be used as shared buffer */
			err = get_shared_buff(hdl);
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
		args->session_hdl = 0u; /* force an invalid value.*/
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
