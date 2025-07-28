// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "test_common.h"
#include "hsm_api.h"
#include "test_importkey.h"

open_session_args_t open_session_args;
hsm_hdl_t hsm_session_hdl;

void hsm_test_sig_handler(int ht_signo, siginfo_t *ht_siginfo, void *ht_sigctx)
{
	hsm_close_session(hsm_session_hdl);

	exit(EXIT_SUCCESS);
}

void se_tools_usage(void)
{
	printf("se_tools usage: se_tools [options]\n");
	printf("Options:\n");
	printf("-i or --info: show Global Info only.\n");
	printf("-d or --dev-info: show device info.\n");
#ifdef PSA_COMPLIANT
	printf("-t or --dev-attest: attest the device and show device-attested info.\n");
	printf("-e or --get-event: show list of active events.\n");
	printf("-u or --lc_update <LC_STATE>: for life-cycle update only\n");
	printf("\t where, permitted values for LC_STATE are:");
	printf("\n\t\tHSM_NXP_PROVISIONED_STATE,");
	printf("\n\t\tHSM_OEM_OPEN_STATE,");
	printf("\n\t\tHSM_OEM_CLOSE_STATE,");
	printf("\n\t\tHSM_OEM_FIELD_RET_STATE,");
	printf("\n\t\tHSM_NXP_FIELD_RET_STATE,");
	printf("\n\t\tHSM_OEM_LOCKED_STATE\n");
#endif
}

#ifdef PSA_COMPLIANT
static int get_lc_state(const char *ascii_state_str)
{
	if (!ascii_state_str)
		return 0;

	if (strcmp("HSM_NXP_PROVISIONED_STATE", ascii_state_str) == 0)
		return HSM_NXP_PROVISIONED_STATE;
	if (strcmp("HSM_OEM_OPEN_STATE", ascii_state_str) == 0)
		return HSM_OEM_OPEN_STATE;
	if (strcmp("HSM_OEM_CLOSE_STATE", ascii_state_str) == 0)
		return HSM_OEM_CLOSE_STATE;
	if (strcmp("HSM_OEM_FIELD_RET_STATE", ascii_state_str) == 0)
		return HSM_OEM_FIELD_RET_STATE;
	if (strcmp("HSM_NXP_FIELD_RET_STATE", ascii_state_str) == 0)
		return HSM_NXP_FIELD_RET_STATE;
	if (strcmp("HSM_OEM_LOCKED_STATE", ascii_state_str) == 0)
		return HSM_OEM_LOCKED_STATE;

	return 0;
}

int print_hsm_get_event(op_get_event_msg_args_t *hsm_get_event_args)
{
	int i;
	int err = 0;
	uint8_t rsp_code;
	hsm_event_report_info_t *hsm_event_report_list =
				hsm_get_event_args->hsm_event_report_list;

	for (i = 0; i < hsm_get_event_args->num_event_report; i++) {
		printf("\nEvent#%d:", i + 1);

		printf("\n\tCommand ID\t: 0x%02x",
		       hsm_event_report_list[i].event_cmd_id);

		printf("\n\tIPC ID\t\t: 0x%02x",
		       hsm_event_report_list[i].event_ipc_id);
		printf("  (0x01 = MU RTD, 0x02 = MU APPS)");

		printf("\n\tResponse Code");
		rsp_code = hsm_event_report_list[i].event_rsp_code >> 8;
		if ((hsm_event_report_list[i].event_rsp_code & 0xFF)
				== HSM_FATAL_FAILURE) {
			err++;
			printf("\t: FATAL Error code = 0x%02x", rsp_code);
		} else {
			if (hsm_event_report_list[i].event_rsp_code & 0xFF00)
				printf("\t: Warning code = 0x%02x", rsp_code);
		}
	}
	printf("\n\n");

	return err;
}
#endif

int process_option(int opt_arg_count, char **optarg)
{
	hsm_err_t err;

	if (opt_arg_count < 2) {
		se_tools_usage();
		return 0;
	}

	if ((strcmp("--help", optarg[1]) == 0 || strcmp("-h", optarg[1]) == 0)) {
		se_tools_usage();
		return 0;
	}

	if ((strcmp("--info", optarg[1]) == 0 || strcmp("-i", optarg[1]) == 0)) {
		print_global_info();
		return 0;
	}

	if ((strcmp("--dev-info", optarg[1]) == 0 || strcmp("-d", optarg[1]) == 0)) {
		get_device_info(hsm_session_hdl);
		return 0;
	}

#ifdef PSA_COMPLIANT
	if ((strcmp("--dev-attest", optarg[1]) == 0 || strcmp("-t", optarg[1]) == 0)) {
		perform_dev_attestation(hsm_session_hdl);
		get_device_info(hsm_session_hdl);
		return 0;
	}

	if ((strcmp("--get-event", optarg[1]) == 0 || strcmp("-e", optarg[1]) == 0)) {
		op_get_event_msg_args_t hsm_get_event_args;

		err = hsm_get_event(hsm_session_hdl, &hsm_get_event_args);
		if (err != HSM_NO_ERROR) {
			printf("hsm_get_event failed err:0x%x\n", err);
			return 0;
		}
		printf("Checking for HSM events...\n\n");
		err = print_hsm_get_event(&hsm_get_event_args);
		return 0;
	}

	if ((strcmp("--lc-update", optarg[1]) == 0 || strcmp("-u", optarg[1]) == 0)) {
		op_get_event_msg_args_t hsm_get_event_args;

		err = hsm_get_event(hsm_session_hdl, &hsm_get_event_args);
		if (err != HSM_NO_ERROR)
			printf("hsm_get_event failed err:0x%x\n", err);

		printf("Checking for HSM events before doing LC-update.\n\n");
		err = print_hsm_get_event(&hsm_get_event_args);
		if (hsm_get_event_args.num_event_report && err) {
			printf("Due HSM events, Life Cycle update is not done.\n");
			return 0;
		}
		if (opt_arg_count == 3)
			lc_update_info(hsm_session_hdl, get_lc_state(optarg[2]));
		else
			se_tools_usage();

		return 0;
	}
#endif
}

int main(int argc, char *argv[])
{
	struct sigaction hsm_test_sigact = {0};
	hsm_err_t err;

	sigemptyset(&hsm_test_sigact.sa_mask);
	hsm_test_sigact.sa_flags = SA_SIGINFO;
	hsm_test_sigact.sa_sigaction = hsm_test_sig_handler;

	/* Register hsm test signal handler for SIGINT (CTRL+C) signal. */
	if (sigaction(SIGINT, &hsm_test_sigact, NULL)) {
		perror("failed to register hsm_test_sig_handler\n");
		return 0;
	}

	open_session_args.mu_type = HSM1;
	err = hsm_open_session(&open_session_args, &hsm_session_hdl);
	if (err != HSM_NO_ERROR) {
		printf("hsm_open_session failed err:0x%x\n", err);
		return 0;
	}

	process_option(argc, argv);

	if (open_session_args.session_hdl) {
		err = hsm_close_session(open_session_args.session_hdl);
		open_session_args.session_hdl = 0;
	}

	return 0;
}

