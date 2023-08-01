// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "common.h"
#include "she_api.h"
#include "plat_utils.h"

she_hdl_t she_session_hdl;

void she_test_sig_handler(int ht_signo, siginfo_t *ht_siginfo, void *ht_sigctx)
{
	she_close_session(she_session_hdl);

	exit(EXIT_SUCCESS);
}

void plat_she_test_usage(void)
{
	printf("she_test usage: she_test [options]\n");
	printf("Options:\n");
}

/* Test entry function. */
int main(int argc, char *argv[])
{
	struct sigaction she_test_sigact = {0};
	open_session_args_t open_session_args = {0};
	op_get_status_args_t op_get_status_args = {0};
	she_err_t err;

	if (argc == 2 && (strcmp("--help", argv[1]) == 0 || strcmp("-h", argv[1]) == 0)) {
		plat_she_test_usage();
		return 0;
	}

	sigemptyset(&she_test_sigact.sa_mask);
	she_test_sigact.sa_flags = SA_SIGINFO;
	she_test_sigact.sa_sigaction = she_test_sig_handler;

	/* Register she test signal handler for SIGINT (CTRL+C) signal. */
	if (sigaction(SIGINT, &she_test_sigact, NULL)) {
		perror("failed to register she_test_sig_handler\n");
		return 0;
	}

	err = she_open_session(&open_session_args, &she_session_hdl);
	if (err != SHE_NO_ERROR) {
		printf("she_open_session failed err:0x%x\n", err);
		return 0;
	}
	printf("she_open_session PASS\n");

	err = she_get_status(she_session_hdl, &op_get_status_args);
	if (!err)
		se_print("CMD_GET_STATUS successful 0x%x\n",
			 op_get_status_args.sreg);

	err = do_she_rng_test(she_session_hdl);
	if (err)
		se_print("Error[0x%x]: RNG test Failed.\n", err);

	se_print("RNG test Passed\n");

	err = she_get_status(she_session_hdl, &op_get_status_args);
	if (!err)
		se_print("CMD_GET_STATUS successful 0x%x\n",
			 op_get_status_args.sreg);

	err = do_she_key_update_test(she_session_hdl);
	if (err)
		se_print("Error[0x%x]: Key Update test Failed.\n", err);

	se_print("Key update test Passed\n");

	err = she_close_session(she_session_hdl);

	printf("she_close_session ret:0x%x\n", err);
	return 0;
}
