// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <stdio.h>

#include "hsm_api.h"
#include "test_common.h"

#ifdef PSA_COMPLIANT
uint8_t test_key_store_status(hsm_hdl_t sess_hdl, uint32_t key_store_id)
{
	hsm_err_t err;
	op_key_store_status_args_t args = {0};

	printf("-------------------------------------------\n");
	printf("Key Store (0x%x) status\n", key_store_id);
	printf("-------------------------------------------\n");

	err = hsm_get_key_store_status(sess_hdl, key_store_id, &args);
	if (err != HSM_NO_ERROR) {
		printf("\nKey store status --> FAILED.\n");
		return TEST_FAILED;
	}

	printf("Exist status: %d...", args.exist_status);
	printf("Open status: %d\n", args.open_status);
	printf("Number of keys: %d\n", args.num_keys_status);
	printf("Number of sessions using the key store: %d\n", args.num_sess_status);
	printf("-------------------------------------------\n");

	return TEST_SUCCESS;
}
#endif
