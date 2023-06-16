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

	err = she_close_session(she_session_hdl);

	printf("she_close_session ret:0x%x\n", err);
	return 0;
}
