// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>

#include "hsm_api.h"
#include "plat_utils.h"

#include "common.h"
#include "ele_perf.h"

hsm_hdl_t hsm_session_hdl;
hsm_hdl_t key_store_hdl;

static time_t perf_run_time;

static uint8_t *perf_tv_fpaths[PERF_SUPPORTED_OP_N] = {
					PERF_CIPHER_FPATH,
					PERF_MAC_FPATH,
					PERF_SIGN_VERIFY_FPATH,
				};

hsm_hdl_t get_hsm_session_hdl(void)
{
	return hsm_session_hdl;
}

void hsm_test_sig_handler(int ht_signo, siginfo_t *ht_siginfo, void *ht_sigctx)
{
	hsm_close_key_store_service(key_store_hdl);
	hsm_close_session(hsm_session_hdl);

	exit(EXIT_SUCCESS);
}

time_t get_ele_perf_time(void)
{
	return perf_run_time;
}

void ele_hsm_perf_test_usage(void)
{
	printf("ele_hsm_perf_test usage: ele_hsm_perf_test [options]\n");
	printf("Options:\n");
	printf("<number of seconds>  <test_vector_path>\n");
	printf("\t<number of seconds> : Number of seconds for which ");
	printf("Performance Benchmarking need to run on each test case\n");
	printf("\t\t\t\t(default: 1 sec, accepted range: 1<=seconds<=10)\n");
	printf("\t<test_vector_path> : Path of test vector file to run ");
	printf("Performance Benchmarking on single test file\n");
	printf("\t\t\t\t(default: all PERF supported test vectors)\n");
}

/* Test entry function. */
int main(int argc, char *argv[])
{
	struct sigaction hsm_test_sigact = {0};
	open_session_args_t open_session_args = {0};
	open_svc_key_store_args_t open_svc_key_store_args = {0};
	hsm_err_t err;

	perf_run_time = DEFAULT_TIME_PER_OP;

	if (argc == 2 && (strcmp("--help", argv[1]) == 0 || strcmp("-h", argv[1]) == 0)) {
		ele_hsm_perf_test_usage();
		goto out;
	}

	if (argc > 1)
		perf_run_time = atoi(argv[1]);

	/*
	 * If Number of seconds per op, is outside accepted range, or
	 * Number of arguments greater than defined, print usage and exit.
	 */
	if (argc > 3 || !(perf_run_time >= 1 && perf_run_time <= 10)) {
		ele_hsm_perf_test_usage();
		goto out;
	}

	sigemptyset(&hsm_test_sigact.sa_mask);
	hsm_test_sigact.sa_flags = SA_SIGINFO;
	hsm_test_sigact.sa_sigaction = hsm_test_sig_handler;

	/*
	 * Register hsm test signal handler for SIGINT (CTRL+C) signal.
	 */
	if (sigaction(SIGINT, &hsm_test_sigact, NULL)) {
		perror("failed to register hsm_test_sig_handler\n");
		goto out;
	}

	do {
		open_session_args.session_priority = 0;
		open_session_args.operating_mode = 0;
		err = hsm_open_session(&open_session_args,
				       &hsm_session_hdl);

		if (err != HSM_NO_ERROR) {
			printf("hsm_open_session failed err:0x%x\n", err);
			break;
		}

		printf("hsm_open_session PASS ret:0x%x\n", err);

		open_svc_key_store_args.key_store_identifier = 0xABCD;
		open_svc_key_store_args.authentication_nonce = 0x1234;
#ifndef PSA_COMPLIANT
		open_svc_key_store_args.max_updates_number   = 100;
#endif
		open_svc_key_store_args.flags = HSM_SVC_KEY_STORE_FLAGS_CREATE;

		err = hsm_open_key_store_service(hsm_session_hdl,
						 &open_svc_key_store_args,
						 &key_store_hdl);

		printf("hsm_open_key_store_service (create) ret:0x%x\n", err);

		if (err == HSM_KEY_STORE_CONFLICT) {
			open_svc_key_store_args.flags = 0;
			err = hsm_open_key_store_service(hsm_session_hdl,
							 &open_svc_key_store_args,
							 &key_store_hdl);
			printf("\nhsm_open_key_store_service (load) ret:0x%x\n", err);
		}

		if (argc > 2) {
			/*
			 * Run Performance Benchmarking on single test vector
			 * file.
			 */
			tv_tests_run(key_store_hdl, argv[2]);
		} else {
			/*
			 * Run Performance Benchmarking on Test Vectors of
			 * ELE Perf supported Crypto Operations.
			 */
			for (uint8_t i = 0; i < PERF_SUPPORTED_OP_N; i++)
				tv_tests_run(key_store_hdl, perf_tv_fpaths[i]);
		}

		err = hsm_close_key_store_service(key_store_hdl);
		printf("hsm_close_key_store_service ret:0x%x\n", err);

		err = hsm_close_session(hsm_session_hdl);
		printf("hsm_close_session ret:0x%x\n", err);

	} while (0);

out:
	return 0;
}
