// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 - 2024 NXP
 */

#include <string.h>
#include "she_api.h"
#include "plat_utils.h"

she_err_t she_ECU_key_update_test(she_hdl_t utils_handle)
{
	op_key_update_args_t key_update_args = {0};
	uint8_t m1[SHE_KEY_SIZE_IN_BYTES] = {0x00, 0x00, 0x00, 0x00,
					     0x00, 0x00, 0x00, 0x00,
					     0x00, 0x00, 0x00, 0x00,
					     0x00, 0x00, 0x00, 0x11};

	/*
	 * ./memory_update_protocol.py 1 1 0x000102030405060708090a0b0c0d0e0f
	 *			0x0000000000000000000000000000000 -c 1 -f 4
	 */
	uint8_t m2[2 * SHE_KEY_SIZE_IN_BYTES] = {0xFF, 0x8B, 0x75, 0xF7,
						 0x3E, 0x6A, 0xD5, 0xA1,
						 0x72, 0x94, 0x23, 0xC6,
						 0xE9, 0x31, 0x1F, 0x1A,
						 0x7B, 0x15, 0x20, 0x23,
						 0xF0, 0x3F, 0xA3, 0x56,
						 0xA3, 0x3F, 0x10, 0x1C,
						 0x3E, 0x81, 0x95, 0xFE};
	uint8_t m3[SHE_KEY_SIZE_IN_BYTES] = {0x7B, 0x7B, 0x9D, 0xE2,
					     0xCE, 0xF6, 0xC5, 0xC1,
					     0x43, 0xCF, 0xF2, 0x64,
					     0x8B, 0xF3, 0x1B, 0x2F};

	/*
	 * ./memory_update_protocol.py 1 1 0x00000000000000000000000000000000
	 *			0x000102030405060708090a0b0c0d0e0f -c 2
	 */
	uint8_t m2_1[2 * SHE_KEY_SIZE_IN_BYTES] = {0x1E, 0x07, 0x72, 0xD9,
						   0x9E, 0x35, 0x03, 0xDF,
						   0x19, 0x62, 0xD4, 0x77,
						   0x2B, 0x9A, 0x28, 0xD9,
						   0xE2, 0x3E, 0xE2, 0x8E,
						   0x7F, 0xCD, 0x75, 0x3D,
						   0x3F, 0x07, 0x67, 0x28,
						   0x7F, 0x09, 0x08, 0x40};
	uint8_t m3_1[SHE_KEY_SIZE_IN_BYTES] = {0x40, 0x13, 0x6E, 0x98,
					       0xFB, 0x36, 0xF9, 0xA0,
					       0x8B, 0x05, 0xF9, 0x9D,
					       0x15, 0x17, 0x53, 0x40};

	uint8_t m4[2 * SHE_KEY_SIZE_IN_BYTES] = {0};
	uint8_t m5[SHE_KEY_SIZE_IN_BYTES] = {0};
	she_err_t err;

	/*
	 * ./memory_update_protocol.py 1 1 0x000102030405060708090a0b0c0d0e0f
	 *			0x0000000000000000000000000000000 -c 3
	 */
	uint8_t m2_2[2 * SHE_KEY_SIZE_IN_BYTES] = {0xA7, 0x3D, 0x02, 0x0C,
						   0xC4, 0xD7, 0x82, 0x5C,
						   0x93, 0x47, 0xD3, 0x01,
						   0xBE, 0x27, 0xE2, 0x04,
						   0x33, 0x48, 0x1A, 0xFD,
						   0xF0, 0x91, 0x27, 0x5B,
						   0x71, 0x13, 0x3B, 0x64,
						   0x08, 0x26, 0x39, 0x9C};
	uint8_t m3_2[SHE_KEY_SIZE_IN_BYTES] = {0xEF, 0x5C, 0x41, 0xD7,
					       0x6C, 0x2E, 0x5B, 0x6E,
					       0x4D, 0x3B, 0xB6, 0xA8,
					       0xFA, 0xC3, 0x7E, 0x6F};

	key_update_args.key_ext = 0x00;
	key_update_args.key_id = SHE_MASTER_ECU_KEY | key_update_args.key_ext;
	key_update_args.m1 = m1;
	key_update_args.m2 = m2;
	key_update_args.m3 = m3;
	key_update_args.m4 = m4;
	key_update_args.m5 = m5;
	key_update_args.m1_size = sizeof(m1);
	key_update_args.m2_size = sizeof(m2);
	key_update_args.m3_size = sizeof(m3);
	key_update_args.m4_size = sizeof(m4);
	key_update_args.m5_size = sizeof(m5);

	err = she_key_update(utils_handle, &key_update_args);
	if (err) {
		se_err("Error[0x%x]: she_key_update failed (ECU).\n", err);
		return err;
	}
	se_print("SHE KEY UPDATE TEST SHE_MASTER_ECU_KEY --> PASSED\n");

	memset(&key_update_args, 0, sizeof(key_update_args));
	key_update_args.key_ext = 0x00;
	key_update_args.key_id = SHE_MASTER_ECU_KEY | key_update_args.key_ext;
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
		se_err("Error[0x%x]: she_key_update failed (NULL ECU).\n", err);
		return err;
	}
	se_print("SHE KEY UPDATE TEST SHE_MASTER_ECU_KEY (NULL) --> PASSED\n");

	memset(&key_update_args, 0, sizeof(key_update_args));
	key_update_args.key_ext = 0x00;
	key_update_args.key_id = SHE_MASTER_ECU_KEY | key_update_args.key_ext;
	key_update_args.m1 = m1;
	key_update_args.m2 = m2_2;
	key_update_args.m3 = m3_2;
	key_update_args.m4 = m4;
	key_update_args.m5 = m5;
	key_update_args.m1_size = sizeof(m1);
	key_update_args.m2_size = sizeof(m2_2);
	key_update_args.m3_size = sizeof(m3_2);
	key_update_args.m4_size = sizeof(m4);
	key_update_args.m5_size = sizeof(m5);

	err = she_key_update(utils_handle, &key_update_args);
	if (err) {
		se_err("Error[0x%x]: she_key_update failed (ECU-2).\n", err);
		return err;
	}
	se_print("SHE KEY UPDATE TEST SHE_MASTER_ECU_KEY (ECU-2) --> PASSED\n");

	return err;
}

she_err_t she_BMK_key_update_test(she_hdl_t utils_handle)
{
	op_key_update_args_t key_update_args = {0};
	uint8_t m1[SHE_KEY_SIZE_IN_BYTES] = {0x00, 0x00, 0x00, 0x00,
					     0x00, 0x00, 0x00, 0x00,
					     0x00, 0x00, 0x00, 0x00,
					     0x00, 0x00, 0x00, 0x21};
	/*
	 * ./memory_update_protocol.py 2 1 0x000102030405060708090a0b0c0d0f0f
	 *			0x000102030405060708090a0b0c0d0e0f -c 1 -f 4
	 */
	uint8_t m2[2 * SHE_KEY_SIZE_IN_BYTES] = {0x2B, 0x11, 0x1E, 0x2D,
						 0x93, 0xF4, 0x86, 0x56,
						 0x6B, 0xCB, 0xBA, 0x1D,
						 0x7F, 0x7A, 0x97, 0x97,
						 0x02, 0xA2, 0x03, 0x58,
						 0x5C, 0xB0, 0x7C, 0x83,
						 0xBB, 0xF8, 0xA8, 0x86,
						 0x89, 0x3F, 0x1B, 0x63};
	uint8_t m3[SHE_KEY_SIZE_IN_BYTES] = {0x40, 0xF3, 0x84, 0xB8,
					     0x13, 0xD2, 0x31, 0x44,
					     0x3A, 0x04, 0xF8, 0xEE,
					     0x02, 0xBF, 0x5A, 0xA3};
	uint8_t m4[2 * SHE_KEY_SIZE_IN_BYTES] = {0};
	uint8_t m5[SHE_KEY_SIZE_IN_BYTES] = {0};
	she_err_t err;

	key_update_args.key_ext = 0;
	key_update_args.key_id = SHE_BOOT_MAC_KEY | key_update_args.key_ext;
	key_update_args.m1 = m1;
	key_update_args.m2 = m2;
	key_update_args.m3 = m3;
	key_update_args.m4 = m4;
	key_update_args.m5 = m5;
	key_update_args.m1_size = sizeof(m1);
	key_update_args.m2_size = sizeof(m2);
	key_update_args.m3_size = sizeof(m3);
	key_update_args.m4_size = sizeof(m4);
	key_update_args.m5_size = sizeof(m5);

	err = she_key_update(utils_handle, &key_update_args);
	if (err) {
		se_err("Error[0x%x]: she_key_update failed (BMK).\n", err);
		return err;
	}
	se_print("SHE KEY UPDATE TEST SHE_BOOT_MAC_KEY --> PASSED\n");

	return err;
}

she_err_t she_key_update_ext_test(she_hdl_t utils_handle)
{
	op_key_update_ext_args_t key_update_ext_args = {0};
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
	/*
	 * ./memory_update_protocol.py 11 1 0x86543782965437bdceaf873465378ffe
	 * 0x000102030405060708090a0b0c0d0e0f  -c 1 (EXT_1)
	 */
	uint8_t m2_8[2 * SHE_KEY_SIZE_IN_BYTES] = {0xA6, 0xC4, 0xD8, 0xF6,
						   0x32, 0xFA, 0xED, 0x10,
						   0x3D, 0x8E, 0x3E, 0xEF,
						   0x2B, 0x76, 0x94, 0xA9,
						   0xF8, 0x4B, 0x2E, 0x6F,
						   0xAC, 0x29, 0x2A, 0x18,
						   0x55, 0xF0, 0xF7, 0xC1,
						   0xE1, 0xEF, 0x14, 0xF4};
	uint8_t m3_8[SHE_KEY_SIZE_IN_BYTES] = {0xCE, 0x24, 0x8F, 0x1F,
					       0x58, 0xC8, 0xA9, 0x78,
					       0x6A, 0xCC, 0xF8, 0x83,
					       0x1E, 0xE4, 0x01, 0xD9};
	/*
	 * ./memory_update_protocol.py 11 1 0x86543782965437bdceaf873465379999
	 * 0x000102030405060708090a0b0c0d0e0f  -c 2 (EXT_1)
	 */
	uint8_t m2_8_1[2 * SHE_KEY_SIZE_IN_BYTES] = {0x7A, 0x4D, 0x2B, 0xD7,
						     0xDD, 0x58, 0x15, 0x41,
						     0x45, 0xC4, 0x1B, 0x20,
						     0x4F, 0xCC, 0x03, 0xC1,
						     0x05, 0x21, 0x77, 0xF5,
						     0x71, 0x32, 0x8C, 0x66,
						     0xFD, 0x84, 0x6C, 0x23,
						     0x39, 0xA5, 0x22, 0x47};
	uint8_t m3_8_1[SHE_KEY_SIZE_IN_BYTES] = {0xAE, 0xF4, 0x02, 0x0C,
						 0x37, 0xA0, 0x1D, 0x94,
						 0x7A, 0x53, 0xE6, 0x12,
						 0x4F, 0xAD, 0xAF, 0xA0};

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
		se_err("Error[0x%x]: she_key_update_ext failed (KEY 6).\n", err);
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
		se_err("Error[0x%x]: she_key_update_ext failed (KEY 7).\n", err);
		return err;
	}
	se_print("SHE KEY UPDATE EXT TEST FOR KEY_7 --> PASSED\n");

	m1[15] = 0xb1;
	memset(&key_update_ext_args, 0, sizeof(key_update_ext_args));
	key_update_ext_args.key_ext = SHE_KEY_N_EXT_1;
	key_update_ext_args.key_id = SHE_KEY_8 | key_update_ext_args.key_ext;
	key_update_ext_args.flags = SHE_LOAD_KEY_EXT_FLAGS_STRICT_OPERATION;
	key_update_ext_args.m1 = m1;
	key_update_ext_args.m2 = m2_8;
	key_update_ext_args.m3 = m3_8;
	key_update_ext_args.m4 = m4;
	key_update_ext_args.m5 = m5;
	key_update_ext_args.m1_size = sizeof(m1);
	key_update_ext_args.m2_size = sizeof(m2_8);
	key_update_ext_args.m3_size = sizeof(m3_8);
	key_update_ext_args.m4_size = sizeof(m4);
	key_update_ext_args.m5_size = sizeof(m5);

	err = she_key_update_ext(utils_handle, &key_update_ext_args);
	if (err) {
		se_err("Error[0x%x]: she_key_update_ext failed (KEY 8).\n", err);
		return err;
	}
	se_print("SHE KEY UPDATE EXT TEST FOR KEY_8 --> PASSED\n");

	m1[15] = 0xb1;
	memset(&key_update_ext_args, 0, sizeof(key_update_ext_args));
	key_update_ext_args.key_ext = SHE_KEY_N_EXT_1;
	key_update_ext_args.key_id = SHE_KEY_8 | key_update_ext_args.key_ext;
	key_update_ext_args.flags = SHE_LOAD_KEY_EXT_FLAGS_STRICT_OPERATION;
	key_update_ext_args.m1 = m1;
	key_update_ext_args.m2 = m2_8_1;
	key_update_ext_args.m3 = m3_8_1;
	key_update_ext_args.m4 = m4;
	key_update_ext_args.m5 = m5;
	key_update_ext_args.m1_size = sizeof(m1);
	key_update_ext_args.m2_size = sizeof(m2_8_1);
	key_update_ext_args.m3_size = sizeof(m3_8_1);
	key_update_ext_args.m4_size = sizeof(m4);
	key_update_ext_args.m5_size = sizeof(m5);

	err = she_key_update_ext(utils_handle, &key_update_ext_args);
	if (err) {
		se_err("Error[0x%x]: she_key_update_ext failed (KEY 8-1).\n", err);
		return err;
	}
	se_print("SHE KEY UPDATE EXT TEST FOR KEY_8-1 --> PASSED\n");

	return err;
}

she_err_t she_key_update_test(she_hdl_t utils_handle)
{
	op_key_update_args_t key_update_args = {0};
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
	uint8_t m2_5[2 * SHE_KEY_SIZE_IN_BYTES] = {0xe0, 0xd0, 0x8b, 0xc3,
						   0x17, 0x36, 0x34, 0x5a,
						   0x16, 0x78, 0x57, 0x2d,
						   0xf7, 0x1f, 0x22, 0xec,
						   0x4a, 0xaf, 0x2f, 0xed,
						   0xcd, 0x28, 0xa6, 0xfc,
						   0xb4, 0xe4, 0x11, 0xd3,
						   0x04, 0xb5, 0x53, 0x1f};
	uint8_t m3_5[SHE_KEY_SIZE_IN_BYTES] = {0x87, 0x7b, 0x6b, 0x2f,
					       0x90, 0xbb, 0x2d, 0x10,
					       0x4b, 0xb5, 0x0e, 0x57,
					       0x6c, 0x3a, 0xc3, 0xf7};
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
	uint8_t m2_ram[2 * SHE_KEY_SIZE_IN_BYTES] = {0x15, 0x28, 0x76, 0xf2,
						     0x9d, 0xc7, 0xca, 0x8d,
						     0x18, 0xe3, 0x8d, 0x70,
						     0x37, 0x44, 0x92, 0xb0,
						     0x36, 0xf2, 0x0b, 0x10,
						     0x90, 0x65, 0x52, 0x33,
						     0x65, 0xeb, 0xd8, 0xab,
						     0x0e, 0x0a, 0x87, 0x31};
	uint8_t m3_ram[SHE_KEY_SIZE_IN_BYTES] = {0xf1, 0x72, 0xe0, 0xd9,
						 0x72, 0xd3, 0xf4, 0xc4,
						 0x4c, 0x9a, 0x2b, 0x12,
						 0x1b, 0x15, 0xa7, 0x2f};
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
		se_err("Error[0x%x]: she_key_update failed (KEY 1).\n", err);
		return err;
	}
	se_print("SHE KEY UPDATE TEST FOR KEY 1 --> PASSED\n");

	m1[15] = 0x88;
	memset(&key_update_args, 0, sizeof(key_update_args));
	key_update_args.key_ext = 0x00;
	key_update_args.key_id = SHE_KEY_5 | key_update_args.key_ext;
	key_update_args.m1 = m1;
	key_update_args.m2 = m2_5;
	key_update_args.m3 = m3_5;
	key_update_args.m4 = m4;
	key_update_args.m5 = m5;
	key_update_args.m1_size = sizeof(m1);
	key_update_args.m2_size = sizeof(m2_5);
	key_update_args.m3_size = sizeof(m3_5);
	key_update_args.m4_size = sizeof(m4);
	key_update_args.m5_size = sizeof(m5);

	err = she_key_update(utils_handle, &key_update_args);
	if (err) {
		se_err("Error[0x%x]: she_key_update failed (KEY 5).\n", err);
		return err;
	}
	se_print("SHE KEY UPDATE TEST FOR KEY_5 --> PASSED\n");

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
		se_err("Error[0x%x]: she_key_update failed (KEY 10).\n", err);
		return err;
	}
	se_print("SHE KEY UPDATE TEST FOR KEY_10 --> PASSED\n");

	m1[15] = 0xed;
	memset(&key_update_args, 0, sizeof(key_update_args));
	key_update_args.key_ext = 0x00;
	key_update_args.key_id = SHE_RAM_KEY | key_update_args.key_ext;
	key_update_args.m1 = m1;
	key_update_args.m2 = m2_ram;
	key_update_args.m3 = m3_ram;
	key_update_args.m4 = m4;
	key_update_args.m5 = m5;
	key_update_args.m1_size = sizeof(m1);
	key_update_args.m2_size = sizeof(m2_ram);
	key_update_args.m3_size = sizeof(m3_ram);
	key_update_args.m4_size = sizeof(m4);
	key_update_args.m5_size = sizeof(m5);

	err = she_key_update(utils_handle, &key_update_args);
	if (err) {
		se_err("Error[0x%x]: she_key_update failed (RAM_KEY).\n", err);
		return err;
	}
	se_print("SHE KEY UPDATE TEST FOR RAM_KEY --> PASSED\n");

	return err;
}

she_err_t do_she_key_update_test(she_hdl_t utils_handle)
{
	she_err_t err;

	se_print("------ KEY UPDATE TEST STARTING ------\n");
	err = she_ECU_key_update_test(utils_handle);
	if (err)
		se_print("ECU KEY UPDATE TEST ---> FAILED\n\n");
	else
		se_print("ECU KEY UPDATE TEST ---> PASSED\n\n");

	err = she_BMK_key_update_test(utils_handle);
	if (err)
		se_print("BMK KEY UPDATE TEST ---> FAILED\n\n");
	else
		se_print("BMK KEY UPDATE TEST ---> PASSED\n\n");

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
