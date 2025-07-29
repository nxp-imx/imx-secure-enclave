// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "hsm_api.h"
#include "crrm_utils.h"

#include "internal/hsm_utils.h"
#include "internal/hsm_session.h"

static open_session_args_t open_session_args = {0};
static hsm_hdl_t crrm_session_hdl;

void crrm_test_sig_handler(int ht_signo,
			   siginfo_t *ht_siginfo,
			   void *ht_sigctx)
{
	hsm_close_session(crrm_session_hdl);
	exit(EXIT_SUCCESS);
}

void crrm_test_usage(void)
{
	printf("------------------------------------------------------------------\n");
	printf("ele_crrm_test can be used to run:\n");
	printf("- functional testing (continuous refresh timer)\n");
	printf("- Expire AWDT timer\n");
	printf("- execute recovery install\n");
	printf("- Get Timer Status\n");
	printf("\nFor running functional test:\n");
	printf("ele_crrm_test -f timer_period (in msec) refresh_period (in msec)\n");
	printf("\ttimer_period (in msec) : Timer value to be set for AWDT\n");
	printf("\trefresh_period (in msec) : Delay after which");
	printf("       AWDT timer should be refreshed\n");
	printf("\nFor expiring AWDT timer:\n");
	printf("ele_crrm_test -k\n");
	printf("\nFor executing recovery install:\n");
	printf("ele_crrm_test -r\n");
	printf("\nTo get Timer status:\n");
	printf("ele_crrm_test -s\n");
	printf("------------------------------------------------------------------\n");
}

void execute_crrm_kill_test(void)
{
	hsm_err_t err;

	err = crrm_test_kill_timer(crrm_session_hdl);
	if (err)
		printf("CRRM AWDT expired timer test FAILED\n");

	err = crrm_test_get_AWDT_status(crrm_session_hdl);
	if (err)
		printf("CRRM GET AWDT STATUS test FAILED\n");
}

void execute_crrm_recovery_test(void)
{
	hsm_err_t err;

	err = crrm_test_recovery_install(crrm_session_hdl);
	if (err)
		printf("CRRM RECOVERY INSTALL test FAILED\n");
}

void execute_crrm_get_status_test(void)
{
	hsm_err_t err;

	err = crrm_test_get_AWDT_status(crrm_session_hdl);
	if (err)
		printf("CRRM GET AWDT STATUS test FAILED\n");
}

void execute_crrm_tests(uint32_t timer_period, uint32_t refresh_period)
{
	hsm_err_t err;

	err = crrm_test_get_AWDT_status(crrm_session_hdl);
	if (err)
		printf("CRRM GET AWDT STATUS test FAILED\n");

	err = crrm_test_boot_mode(crrm_session_hdl);
	if (err)
		printf("CRRM BOOT MODE test FAILED\n");

	printf("---- REFRESHING TIMER IN LOOP %d %d ----\n",
	       timer_period, refresh_period);
	while (1) {
		err = crrm_test_refresh_AWDT(crrm_session_hdl, timer_period);
		if (err) {
			printf("CRRM REFRESH AWDT test FAILED\n");
			return;
		}
		struct timespec start, current;

		clock_gettime(CLOCK_MONOTONIC_RAW, &start);

		do {
			clock_gettime(CLOCK_MONOTONIC_RAW, &current);
		} while ((current.tv_sec - start.tv_sec) <= refresh_period / 1000);
	}
}

/* Test entry function. */
int main(int argc, char *argv[])
{
	struct sigaction crrm_test_sigact = {0};
	hsm_err_t err = 0;
	uint32_t timer_period = 0;
	uint32_t refresh_period = 0;
	int i = 0;

	sigemptyset(&crrm_test_sigact.sa_mask);
	crrm_test_sigact.sa_flags = SA_SIGINFO;
	crrm_test_sigact.sa_sigaction = crrm_test_sig_handler;

	/* Register crrm test signal handler for SIGINT (CTRL+C) signal. */
	if (sigaction(SIGINT, &crrm_test_sigact, NULL)) {
		perror("failed to register crrm_test_sig_handler\n");
		return 0;
	}

	if (argc == 4) {
		if (strcmp("-f", argv[1]) == 0) {
			err = hsm_open_session(&open_session_args, &crrm_session_hdl);
			if (err != HSM_NO_ERROR) {
				printf("hsm_open_session failed err:0x%x\n", err);
				return -1;
			}
			printf("hsm_open_session PASS 0x%x\n", crrm_session_hdl);

			timer_period = atoi(argv[2]);
			refresh_period = atoi(argv[3]);
			printf(" %d : %d\n", timer_period, refresh_period);
			execute_crrm_tests(timer_period, refresh_period);
			if (open_session_args.session_hdl) {
				err = hsm_close_session(open_session_args.session_hdl);
				printf("hsm_close_session ret:0x%x\n", err);
			}
		} else {
			crrm_test_usage();
		}
		return 0;
	} else if (argc == 2) {
		if (strcmp("--help", argv[1]) == 0 || strcmp("-h", argv[1]) == 0) {
			crrm_test_usage();
			return 0;
		}
		err = hsm_open_session(&open_session_args, &crrm_session_hdl);
		if (err != HSM_NO_ERROR) {
			printf("hsm_open_session failed err:0x%x\n", err);
			return -1;
		}
		printf("hsm_open_session PASS 0x%x\n", crrm_session_hdl);

		if (strcmp("-r", argv[1]) == 0)
			execute_crrm_recovery_test();
		else if (strcmp("-s", argv[1]) == 0)
			execute_crrm_get_status_test();
		else if (strcmp("-k", argv[1]) == 0)
			execute_crrm_kill_test();
		else
			crrm_test_usage();

		if (open_session_args.session_hdl) {
			err = hsm_close_session(open_session_args.session_hdl);
			printf("hsm_close_session ret:0x%x\n", err);
		}
	} else {
		crrm_test_usage();
		return 0;
	}

	return 0;
}
