// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <string.h>
#include "she_api.h"
#include "plat_utils.h"

she_err_t she_key_update_ext_test(she_hdl_t utils_handle)
{
	op_key_update_ext_args_t key_update_ext_args = {0};
	uint8_t i = 0;
	uint8_t m1[SHE_KEY_SIZE_IN_BYTES] = {0x00, 0x00, 0x00, 0x00,
					     0x00, 0x00, 0x00, 0x00,
					     0x00, 0x00, 0x00, 0x00,
					     0x00, 0x00, 0x00, 0x99};
	uint8_t m2_6[2 * SHE_KEY_SIZE_IN_BYTES] = {0x0f, 0x89, 0x64, 0x2a,
						   0x6d, 0x8e, 0xfb, 0xe6,
						   0xb4, 0xac, 0x20, 0x81,
						   0xf0, 0x92, 0xdf, 0xa4,
						   0x42, 0xc3, 0xdf, 0x88,
						   0x43, 0x7e, 0x17, 0xbb,
						   0xfb, 0x16, 0x21, 0xc3,
						   0x69, 0x03, 0xa3, 0xa8};
	uint8_t m3_6[SHE_KEY_SIZE_IN_BYTES] = {0x55, 0xfe, 0x75, 0xfa,
					       0x87, 0x72, 0x15, 0xac,
					       0xbb, 0x62, 0x89, 0x95,
					       0x98, 0x95, 0xaa, 0x51};
	uint8_t m2_7[2 * SHE_KEY_SIZE_IN_BYTES] = {0x6c, 0x24, 0x2d, 0xef,
						   0x71, 0x91, 0x56, 0xef,
						   0x4d, 0xac, 0x70, 0xc5,
						   0xde, 0xc8, 0x05, 0x3d,
						   0x11, 0x03, 0x0a, 0x9c,
						   0x45, 0x5f, 0x2b, 0x2b,
						   0x67, 0xa8, 0xda, 0xd4,
						   0x38, 0x2f, 0x9d, 0x59};
	uint8_t m3_7[SHE_KEY_SIZE_IN_BYTES] = {0xba, 0x54, 0x48, 0x8c,
					       0x20, 0x40, 0xd0, 0xcb,
					       0xe6, 0x62, 0x64, 0x71,
					       0x78, 0x56, 0xfc, 0xba};
	uint8_t m4[2 * SHE_KEY_SIZE_IN_BYTES] = {0};
	uint8_t m5[SHE_KEY_SIZE_IN_BYTES] = {0};
	she_err_t err;

	key_update_ext_args.key_ext = 0x00;
	key_update_ext_args.key_id = SHE_KEY_6 | key_update_ext_args.key_ext;
	key_update_ext_args.flags = SHE_LOAD_KEY_EXT_FLAGS_STRICT_OPERATION;
	key_update_ext_args.m1 = m1;
	key_update_ext_args.m2 = m2_6;
	key_update_ext_args.m3 = m3_6;
	key_update_ext_args.m4 = m4;
	key_update_ext_args.m5 = m5;
	key_update_ext_args.m1_size = sizeof(m1);
	key_update_ext_args.m2_size = sizeof(m2_6);
	key_update_ext_args.m3_size = sizeof(m3_6);
	key_update_ext_args.m4_size = sizeof(m4);
	key_update_ext_args.m5_size = sizeof(m5);

	err = she_key_update_ext(utils_handle, &key_update_ext_args);
	if (err) {
		se_err("Error[0x%x]: she_key_update_ext failed.\n", err);
		return err;
	}
	se_print("SHE KEY UPDATE EXT TEST FOR KEY 6 --> PASSED\n");

	m1[15] = 0xaa;
	memset(&key_update_ext_args, 0, sizeof(key_update_ext_args));
	key_update_ext_args.key_ext = 0x00;
	key_update_ext_args.key_id = SHE_KEY_7 | key_update_ext_args.key_ext;
	key_update_ext_args.flags = SHE_LOAD_KEY_EXT_FLAGS_STRICT_OPERATION;
	key_update_ext_args.m1 = m1;
	key_update_ext_args.m2 = m2_7;
	key_update_ext_args.m3 = m3_7;
	key_update_ext_args.m4 = m4;
	key_update_ext_args.m5 = m5;
	key_update_ext_args.m1_size = sizeof(m1);
	key_update_ext_args.m2_size = sizeof(m2_7);
	key_update_ext_args.m3_size = sizeof(m3_7);
	key_update_ext_args.m4_size = sizeof(m4);
	key_update_ext_args.m5_size = sizeof(m5);

	err = she_key_update_ext(utils_handle, &key_update_ext_args);
	if (err) {
		se_err("Error[0x%x]: she_key_update_ext failed.\n", err);
		return err;
	}
	se_print("SHE KEY UPDATE EXT TEST FOR KEY_7 --> PASSED\n");

	return err;
}

she_err_t she_key_update_test(she_hdl_t utils_handle)
{
	op_key_update_args_t key_update_args = {0};
	uint8_t i = 0;
	uint8_t m1[SHE_KEY_SIZE_IN_BYTES] = {0x00, 0x00, 0x00, 0x00,
					     0x00, 0x00, 0x00, 0x00,
					     0x00, 0x00, 0x00, 0x00,
					     0x00, 0x00, 0x00, 0x44};
	uint8_t m2_1[2 * SHE_KEY_SIZE_IN_BYTES] = {0xe0, 0xd0, 0x8b, 0xc3,
						   0x17, 0x36, 0x34, 0x5a,
						   0x16, 0x78, 0x57, 0x2d,
						   0xf7, 0x1f, 0x22, 0xec,
						   0x4a, 0xaf, 0x2f, 0xed,
						   0xcd, 0x28, 0xa6, 0xfc,
						   0xb4, 0xe4, 0x11, 0xd3,
						   0x04, 0xb5, 0x53, 0x1f};
	uint8_t m3_1[SHE_KEY_SIZE_IN_BYTES] = {0xf0, 0xe9, 0x29, 0x9c,
					       0x43, 0xf9, 0xbe, 0xc6,
					       0x0a, 0x83, 0x10, 0xad,
					       0xdf, 0x25, 0xba, 0xba};
	uint8_t m2_10[2 * SHE_KEY_SIZE_IN_BYTES] = {0x99, 0x34, 0x69, 0x32,
						    0xe0, 0x23, 0xa1, 0xf0,
						    0xa4, 0xc5, 0x1d, 0x5d,
						    0x40, 0xbf, 0xdb, 0xfa,
						    0x63, 0xb4, 0xb1, 0xf6,
						    0xcb, 0xa5, 0x0f, 0x11,
						    0x74, 0x84, 0xa1, 0x9b,
						    0xcf, 0xff, 0x1e, 0x2a};
	uint8_t m3_10[SHE_KEY_SIZE_IN_BYTES] = {0x85, 0x61, 0x0d, 0xbc,
						0xbe, 0xe1, 0x00, 0x3c,
						0xab, 0xde, 0x05, 0x52,
						0x86, 0x2e, 0xa7, 0x62};
	uint8_t m4[2 * SHE_KEY_SIZE_IN_BYTES] = {0};
	uint8_t m5[SHE_KEY_SIZE_IN_BYTES] = {0};
	she_err_t err;

	key_update_args.key_ext = 0x00;
	key_update_args.key_id = SHE_KEY_1 | key_update_args.key_ext;
	key_update_args.m1 = m1;
	key_update_args.m2 = m2_1;
	key_update_args.m3 = m3_1;
	key_update_args.m4 = m4;
	key_update_args.m5 = m5;
	key_update_args.m1_size = sizeof(m1);
	key_update_args.m2_size = sizeof(m2_1);
	key_update_args.m3_size = sizeof(m3_1);
	key_update_args.m4_size = sizeof(m4);
	key_update_args.m5_size = sizeof(m5);

	err = she_key_update(utils_handle, &key_update_args);
	if (err) {
		se_err("Error[0x%x]: she_key_update failed.\n", err);
		return err;
	}
	se_print("SHE KEY UPDATE TEST FOR KEY 1 --> PASSED\n");

	m1[15] = 0xdd;
	memset(&key_update_args, 0, sizeof(key_update_args));
	key_update_args.key_ext = 0x00;
	key_update_args.key_id = SHE_KEY_10 | key_update_args.key_ext;
	key_update_args.m1 = m1;
	key_update_args.m2 = m2_10;
	key_update_args.m3 = m3_10;
	key_update_args.m4 = m4;
	key_update_args.m5 = m5;
	key_update_args.m1_size = sizeof(m1);
	key_update_args.m2_size = sizeof(m2_10);
	key_update_args.m3_size = sizeof(m3_10);
	key_update_args.m4_size = sizeof(m4);
	key_update_args.m5_size = sizeof(m5);

	err = she_key_update(utils_handle, &key_update_args);
	if (err) {
		se_err("Error[0x%x]: she_key_update failed.\n", err);
		return err;
	}
	se_print("SHE KEY UPDATE TEST FOR KEY_10 --> PASSED\n");

	return err;
}

she_err_t do_she_key_update_test(she_hdl_t utils_handle)
{
	she_err_t err;

	se_print("------ KEY UPDATE TEST STARTING ------\n");
	err = she_key_update_test(utils_handle);
	if (err)
		se_print("KEY UPDATE TEST ---> FAILED\n\n");
	else
		se_print("KEY UPDATE TEST ---> PASSED\n\n");

	se_print("------ KEY UPDATE EXT TEST STARTING ------\n");
	err = she_key_update_ext_test(utils_handle);
	if (err)
		se_print("KEY UPDATE EXT TEST ---> FAILED\n\n");
	else
		se_print("KEY UPDATE EXT TEST ---> PASSED\n\n");

	return err;
}
