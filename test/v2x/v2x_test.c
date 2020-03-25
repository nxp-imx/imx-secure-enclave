/*
 * Copyright 2020 NXP
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
#include <stdio.h>

int main(int argc, char *argv[])
{
	open_session_args_t args;
	hsm_hdl_t session_hdl;
	hsm_err_t err;

	// SG0
	args.session_priority = HSM_OPEN_SESSION_PRIORITY_HIGH;
	args.operating_mode = HSM_OPEN_SESSION_LOW_LATENCY_MASK;
	err = hsm_open_session(&args, &session_hdl);
	printf("SG0 hsm_open_session err: 0x%x session_hdl: 0x%08x\n", err, session_hdl);
	//TODO: close session

	// SV0
	args.session_priority = HSM_OPEN_SESSION_PRIORITY_HIGH;
	args.operating_mode = HSM_OPEN_SESSION_LOW_LATENCY_MASK | HSM_OPEN_SESSION_NO_KEY_STORE_MASK;
	err = hsm_open_session(&args, &session_hdl);
	printf("SV0 hsm_open_session err: 0x%x session_hdl: 0x%08x\n", err, session_hdl);
	//TODO: close session

	// SG1
	args.session_priority = HSM_OPEN_SESSION_PRIORITY_LOW;
	args.operating_mode = HSM_OPEN_SESSION_LOW_LATENCY_MASK;
	err = hsm_open_session(&args, &session_hdl);
	printf("SG1 hsm_open_session err: 0x%x session_hdl: 0x%08x\n", err, session_hdl);
	//TODO: close session

	//SV1
	args.session_priority = HSM_OPEN_SESSION_PRIORITY_LOW;
	args.operating_mode = HSM_OPEN_SESSION_LOW_LATENCY_MASK | HSM_OPEN_SESSION_NO_KEY_STORE_MASK;
	err = hsm_open_session(&args, &session_hdl);
	printf("SV1 hsm_open_session err: 0x%x session_hdl: 0x%08x\n", err, session_hdl);
	//TODO: close session

	return 0;
}
