// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "nvm.h"

#include "hsm_exec.h"
#include "shx_test_macros.h"
#include "test_hsm_pub_key_decompression.h"

static uint32_t nvm_status;

/* Start the storage manager.*/
uint32_t test_hsm_start_storage_manager(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;
	uint8_t arg_nvm = 0x00;

	if (system("systemctl status nvm_daemon") == 0) {
		nvm_status = NVM_STATUS_RUNNING;
		return fails;
	} else if (system("systemctl start nvm_daemon")) {
		printf("Error: Failed to start NVM Daemon\n");
		fails = 1;
	}

	while (system("systemctl status nvm_daemon") != 0)
		;

	return fails;
}

/* Start the storage manager.*/
uint32_t test_hsm_start_v2x_storage_manager(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;

	if (system("systemctl status nvm_daemon_v2x") == 0) {
		nvm_status = NVM_STATUS_RUNNING;
		return fails;
	} else if (system("systemctl start nvm_daemon_v2x")) {
		printf("Error: Failed to start NVM Daemon\n");
		fails = 1;
	}

	while (system("systemctl status nvm_daemon_v2x") != 0)
		;

	return fails;
}

/* Test close session */
uint32_t test_hsm_stop_storage_manager(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;

	if (nvm_status == NVM_STATUS_RUNNING)
		return fails;

	if (system("systemctl stop nvm_daemon")) {
		printf("Error: Failed to stop NVM Daemon\n");
		fails = 1;
	}

	while (system("systemctl status nvm_daemon") == 0)
		;
	return fails;
}

/* Test close session */
uint32_t test_hsm_stop_v2x_storage_manager(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;

	if (nvm_status == NVM_STATUS_RUNNING)
		return fails;

	if (system("systemctl stop nvm_daemon_v2x")) {
		printf("Error: Failed to stop NVM Daemon\n");
		fails = 1;
	}

	while (system("systemctl status nvm_daemon_v2x") == 0)
		;

	return fails;
}
