// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "she_api.h"
#include "shx_test.h"
#include "shx_test_sessions.h"
#include "shx_test_macros.h"

/* Test open session */
uint32_t she_test_open_session(she_test_struct_t *testCtx, FILE *fp)
{
	she_hdl_t session_hdl;
	open_session_args_t args = {0};
	uint32_t fails = 0;
	she_err_t err;
	/* read the session index. */
	uint32_t index = READ_VALUE(fp, uint32_t);

	/* read the parameters. */
	args.mu_type = READ_VALUE(fp, uint32_t);

	/* Open the SHE session. */
	err = she_open_session(&args, &session_hdl);
	printf("session_hdl 0x%x\n", session_hdl);
	testCtx[index].she_hdl = session_hdl;
	/* Check there is no error reported. */
	READ_CHECK_POINTER(testCtx[index], fp, testCtx[index].she_hdl);

	return fails;
}

/* Test close session */
uint32_t she_test_close_session(she_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;

	/* read the session index. */
	uint32_t index = shx_read_single_data(fp);

	printf("%s 0x%x\n", __func__, testCtx[index].she_hdl);
	/* Close session if it was opened. */
	she_close_session(testCtx[index].she_hdl);

	/* Reset the hdl to avoid double close. */
	testCtx[index].she_hdl = 0;

	/* Report OK for consistency in test log */
	CHECK_VALUE(testCtx[index], 0, 0);

	return fails;
}
