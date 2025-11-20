// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024-2025 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "she_api.h"
#include "shx_test.h"
#include "shx_test_macros.h"

/* Test Key store Open */
uint32_t she_test_key_store_open(she_test_struct_t *testCtx, FILE *fp)
{
	open_svc_key_store_args_t args = {0};
	uint32_t fails = 0;

	she_err_t err = 1;
	she_err_t expected_err;
	/* read the session index. */
	uint32_t index = READ_VALUE(fp, uint32_t);
	uint32_t key_store_num = READ_VALUE(fp, uint32_t);

	args.key_store_identifier = READ_VALUE(fp, uint32_t);
	args.authentication_nonce = READ_VALUE(fp, uint32_t);
	args.flags = READ_VALUE(fp, uint8_t);
	args.max_updates_number = READ_VALUE(fp, uint16_t);
	args.min_mac_length = READ_VALUE(fp, uint8_t);
	args.signed_msg_size = READ_VALUE(fp, uint16_t);
	args.signed_message = READ_INPUT_BUFFER(fp, args.signed_msg_size);

	err = she_open_key_store_service(testCtx[index].she_hdl, &args);

	if (err == SHE_KEY_STORE_CONFLICT || err == SHE_ID_CONFLICT) {
		args.flags &= ~(KEY_STORE_OPEN_FLAGS_CREATE |
				KEY_STORE_OPEN_FLAGS_SET_MAC_LEN);

		err = she_open_key_store_service(testCtx[index].she_hdl, &args);
	}

	/* read the expected error code and check it. */
	READ_CHECK_VALUE(testCtx[index], fp, err);

	if (args.signed_message)
		free(args.signed_message);

	if (!fails)
		testCtx[index].service_hdl[key_store_num][KEY_STORE] = args.key_store_hdl;

	return fails;
}

/* Test Key store close */
uint32_t she_test_key_store_close(she_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;
	she_err_t err = 1;
	she_err_t expected_err;

	/* read the session index. */
	uint32_t index = READ_VALUE(fp, uint32_t);
	uint32_t key_store_num = READ_VALUE(fp, uint32_t);

	err = she_close_key_store_service
		(testCtx[index].service_hdl[key_store_num][KEY_STORE]);

	/* Reset the hdl to avoid double close. */
	testCtx[index].service_hdl[key_store_num][KEY_STORE] = 0;

	/* read the expected error code and check it. */
	READ_CHECK_VALUE(testCtx[index], fp, err);

	return fails;
}
