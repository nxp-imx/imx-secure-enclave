// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025-2026 NXP
 */

#include "hsm_exec.h"
#include "test_storage_utils.h"

/* Start the storage manager */
uint32_t test_hsm_start_storage_manager(hsm_test_struct_t *testCtx, FILE *fp)
{
	return start_daemon("nvm_daemon") ? 1 : 0;
}

/* Start the V2X storage manager */
uint32_t test_hsm_start_v2x_storage_manager(hsm_test_struct_t *testCtx, FILE *fp)
{
	return start_daemon("nvm_daemon_v2x_hsm.service") ? 1 : 0;
}

/* Stop the storage manager */
uint32_t test_hsm_stop_storage_manager(hsm_test_struct_t *testCtx, FILE *fp)
{
	return stop_daemon("nvm_daemon") ? 1 : 0;
}

/* Stop the V2X storage manager */
uint32_t test_hsm_stop_v2x_storage_manager(hsm_test_struct_t *testCtx, FILE *fp)
{
	return stop_daemon("nvm_daemon_v2x_hsm.service") ? 1 : 0;
}
