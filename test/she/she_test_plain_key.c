// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <string.h>
#include "she_api.h"
#include "plat_utils.h"

she_err_t she_load_plain_key_test(she_hdl_t utils_handle)
{
	op_load_plain_key_args_t load_plain_key_args = {0};
	uint8_t key[SHE_KEY_SIZE_IN_BYTES] = {0x85, 0x61, 0x0d, 0xbc,
					      0xbe, 0xe1, 0x00, 0x3c,
					      0xab, 0xde, 0x05, 0x52,
					      0x86, 0x2e, 0xa7, 0x62};
	she_err_t err;

	memcpy(load_plain_key_args.key, key, SHE_KEY_SIZE_IN_BYTES);

	err = she_load_plain_key(utils_handle, &load_plain_key_args);
	if (err) {
		se_err("Error[0x%x]: she_load_plain_key failed.\n", err);
		return err;
	}
	se_print("SHE LOAD PLAIN KEY TEST --> PASSED\n");

	key[10] = 0x76;

	memcpy(load_plain_key_args.key, key, SHE_KEY_SIZE_IN_BYTES);

	err = she_load_plain_key(utils_handle, &load_plain_key_args);
	if (err) {
		se_err("Error[0x%x]: she_load_plain_key failed.\n", err);
		return err;
	}
	se_print("SHE LOAD PLAIN KEY TEST (2) --> PASSED\n");

	return err;
}

she_err_t she_export_plain_key_test(she_hdl_t utils_handle)
{
	op_export_plain_key_args_t export_plain_key_args = {0};
	uint8_t i = 0;
	uint8_t m1[SHE_KEY_SIZE_IN_BYTES] = {0};
	uint8_t m2[2 * SHE_KEY_SIZE_IN_BYTES] = {0};
	uint8_t m3[SHE_KEY_SIZE_IN_BYTES] = {0};
	uint8_t m4[2 * SHE_KEY_SIZE_IN_BYTES] = {0};
	uint8_t m5[SHE_KEY_SIZE_IN_BYTES] = {0};
	she_err_t err;

	export_plain_key_args.m1 = m1;
	export_plain_key_args.m2 = m2;
	export_plain_key_args.m3 = m3;
	export_plain_key_args.m4 = m4;
	export_plain_key_args.m5 = m5;
	export_plain_key_args.m1_size = sizeof(m1);
	export_plain_key_args.m2_size = sizeof(m2);
	export_plain_key_args.m3_size = sizeof(m3);
	export_plain_key_args.m4_size = sizeof(m4);
	export_plain_key_args.m5_size = sizeof(m5);

	err = she_export_plain_key(utils_handle, &export_plain_key_args);
	if (err) {
		se_err("Error[0x%x]: she_export_plain_key failed.\n", err);
		return err;
	}

	se_print("SHE EXPORT PLAIN KEY TEST --> PASSED\n");

	return err;
}

she_err_t do_she_plain_key_test(she_hdl_t utils_handle)
{
	she_err_t err;

	se_print("------ PLAIN KEY TEST STARTING ------\n");
	err = she_load_plain_key_test(utils_handle);
	if (err)
		se_print("LOAD PLAIN KEY TEST ---> FAILED\n\n");
	else
		se_print("LOAD PLAIN KEY TEST ---> PASSED\n\n");

	err = she_export_plain_key_test(utils_handle);
	if (err)
		se_print("EXPORT PLAIN KEY TEST ---> FAILED\n\n");
	else
		se_print("EXPORT PLAIN KEY TEST ---> PASSED\n\n");

	return err;
}
