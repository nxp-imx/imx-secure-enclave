// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>

#include "internal/hsm_commit.h"

#ifdef PSA_COMPLIANT
// Add helper function to decode info type
static void print_commit_info_type(uint32_t info_type)
{
	printf("Information types to commit (0x%08X):\n", info_type);

	if (info_type & HSM_COMMIT_NXP_SRK_REVOCATION)
		printf("  - NXP SRK revocation\n");
	if (info_type & HSM_COMMIT_NXP_FW_VERSION)
		printf("  - NXP FW version\n");
	if (info_type & HSM_COMMIT_OEM_SRK_REVOCATION)
		printf("  - OEM SRK revocation\n");
	if (info_type & HSM_COMMIT_OEM_FW_VERSION)
		printf("  - OEM FW version\n");
}

static void print_committed_info(uint32_t committed_info)
{
	printf("Information successfully committed (0x%08X):\n", committed_info);

	if (committed_info & HSM_COMMIT_NXP_SRK_REVOCATION)
		printf("  ✓ NXP SRK revocation\n");
	if (committed_info & HSM_COMMIT_NXP_FW_VERSION)
		printf("  ✓ NXP FW version\n");
	if (committed_info & HSM_COMMIT_OEM_SRK_REVOCATION)
		printf("  ✓ OEM SRK revocation\n");
	if (committed_info & HSM_COMMIT_OEM_FW_VERSION)
		printf("  ✓ OEM FW version\n");

	if (committed_info == 0)
		printf("  (None - nothing was committed)\n");
}

hsm_err_t exchange_commit_command(hsm_hdl_t session_hdl, uint32_t info_type)
{
	op_commit_args_t commit_args = {0};
	hsm_err_t err;

	commit_args.info_type = info_type;
	print_commit_info_type(info_type);

	printf("Executing COMMIT command...\n");
	err = hsm_commit(session_hdl, &commit_args);
	if (err == HSM_NO_ERROR) {
		printf("\n✓ SUCCESS: COMMIT operation completed\n\n");
		print_committed_info(commit_args.committed_info);
		return err;
	}
	printf("\n✗ ERROR: COMMIT operation failed\n");
	printf("Error code: 0x%X\n\n", err);

	switch (err) {
	case HSM_GENERAL_ERROR:
		printf("Reason: General error (0x29)\n");
		break;
	case HSM_INVALID_PARAM:
		printf("Reason: Invalid information encoded in request (0xF4)\n");
		break;
	case HSM_EVENT_QUEUE_NOT_EMPTY:
		printf("Reason: Event queue not empty (0xC0)\n");
		printf("Note: When targeting OEM version or OEM SRK revocation,\n");
		printf("      the event queue must be empty.\n");
		printf("      Use --get-event to check for pending events.\n");
		break;
	default:
		printf("Reason: Unknown error [0x%x]\n", err);
		break;
	}
		return err;
}

// Add commit test function
static hsm_err_t test_commit(hsm_hdl_t session_hdl, uint32_t info_type)
{
	printf("\n========================================\n");
	printf("COMMIT Command Test\n");
	printf("========================================\n\n");

	return exchange_commit_command(session_hdl, info_type);
}
#endif
