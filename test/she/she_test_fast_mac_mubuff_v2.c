// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024-2026 NXP
 */

#include <string.h>
#include "she_api.h"
#include "plat_utils.h"

static uint8_t message1[SHE_MAC_SIZE] = {0x6b, 0xc1, 0xbe, 0xe2,
					 0x2e, 0x40, 0x9f, 0x96,
					 0xe9, 0x3d, 0x7e, 0x11,
					 0x73, 0x93, 0x17, 0x2a};
static uint8_t mac1[SHE_MAC_SIZE] = {0x07, 0x0a, 0x16, 0xb4,
				     0x6b, 0x4d, 0x41, 0x44,
				     0xf7, 0x9b, 0xdd, 0x9d,
				     0xd0, 0x4a, 0x28, 0x7c};
static uint8_t message2[40] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
			       0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
			       0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
			       0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
			       0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11};
static uint8_t mac2[SHE_MAC_SIZE] = {0xdf, 0xa6, 0x67, 0x47,
				     0xde, 0x9a, 0xe6, 0x30,
				     0x30, 0xca, 0x32, 0x61,
				     0x14, 0x97, 0xc8, 0x27};
static uint8_t message3[240] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
				0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
				0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
				0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
				0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
				0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
				0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
				0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
				0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
				0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
				0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
				0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
				0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
				0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
				0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
				0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
				0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
				0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
				0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
				0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
				0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
				0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
				0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
				0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
				0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
				0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
				0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
				0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
				0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
				0x30, 0xc8, 0x1c, 0x46, 0x33, 0x55, 0x44, 0x11};
static uint8_t mac3[SHE_MAC_SIZE] = {0xeb, 0x25, 0x70, 0x3e,
				     0x78, 0x51, 0xa7, 0x92,
				     0xd5, 0x7b, 0xc5, 0x2f,
				     0x6e, 0xf0, 0xc9, 0x5e};

void dump_mac(uint8_t *gen_mac, uint8_t *exp_mac)
{
	uint8_t i = 0;

	for (i = 0; i < SHE_MAC_SIZE; i++) {
		if ((i % 10) == 0)
			se_info("\n");
		se_info("%02x:%02x ", gen_mac[i], exp_mac[i]);
	}
	se_info("\n");
}

she_err_t she_verify_fast_mac_mubuff_v2_test(she_hdl_t utils_handle)
{
	op_verify_mac_t verify_mac_args = {0};
	she_err_t err;
	uint8_t i = 0;

	verify_mac_args.key_ext = 0x00;
	verify_mac_args.key_id = SHE_KEY_1;
	verify_mac_args.mac = mac1;
	verify_mac_args.mac_length = SHE_MAC_SIZE;
	verify_mac_args.message = message1;
	verify_mac_args.message_length = sizeof(message1);

	err = she_verify_fast_mac_mubuff_v2(utils_handle, &verify_mac_args);
	if (err) {
		se_err("Error[0x%x]: %s failed.\n", err, __func__);
		return err;
	}

	if (verify_mac_args.verification_status == SHE_MAC_VERIFICATION_SUCCESS) {
		se_print("SHE VERIFY FAST MAC MUBUFF V2 (16 BYTES) --> PASSED\n");
	} else {
		se_print("SHE VERIFY FAST MAC MUBUFF V2 (16 BYTES) --> FAILED\n");
		return SHE_GENERAL_ERROR;
	}

	memset(&verify_mac_args, 0, sizeof(verify_mac_args));
	verify_mac_args.key_ext = 0x00;
	verify_mac_args.key_id = SHE_KEY_1;
	verify_mac_args.mac = mac2;
	verify_mac_args.mac_length = SHE_MAC_SIZE;
	verify_mac_args.message = message2;
	verify_mac_args.message_length = sizeof(message2);

	err = she_verify_fast_mac_mubuff_v2(utils_handle, &verify_mac_args);
	if (err) {
		se_err("Error[0x%x]: %s failed.\n", err, __func__);
		return err;
	}

	if (verify_mac_args.verification_status == SHE_MAC_VERIFICATION_SUCCESS) {
		se_print("SHE VERIFY FAST MAC MUBUFF V2 (40 BYTES) --> PASSED\n");
	} else {
		se_print("SHE VERIFY FAST MAC MUBUFF V2 (40 BYTES) --> FAILED\n");
		return SHE_GENERAL_ERROR;
	}

	memset(&verify_mac_args, 0, sizeof(verify_mac_args));
	verify_mac_args.key_ext = 0;
	verify_mac_args.key_id = SHE_KEY_1;
	verify_mac_args.mac = mac3;
	verify_mac_args.mac_length = SHE_MAC_SIZE;
	verify_mac_args.message = message3;
	verify_mac_args.message_length = sizeof(message3);

	err = she_verify_fast_mac_mubuff_v2(utils_handle, &verify_mac_args);
	if (err) {
		se_err("Error[0x%x]: %s failed.\n", err, __func__);
		return err;
	}

	if (verify_mac_args.verification_status == SHE_MAC_VERIFICATION_SUCCESS) {
		se_print("SHE VERIFY FAST MAC MUBUFF V2 (240 BYTES) --> PASSED\n");
	} else {
		se_print("SHE VERIFY FAST MAC MUBUFF V2 (240 BYTES) --> FAILED\n");
		return SHE_GENERAL_ERROR;
	}

	return err;
}

she_err_t she_generate_fast_mac_mubuff_v2_test(she_hdl_t utils_handle)
{
	op_generate_mac_t generate_mac_args = {0};
	she_err_t err;
	uint8_t i = 0;
	uint8_t mac[SHE_MAC_SIZE] = {0};

	generate_mac_args.key_ext = 0x00;
	generate_mac_args.key_id = SHE_KEY_5;
	generate_mac_args.mac = mac;
	generate_mac_args.message = message1;
	generate_mac_args.message_length = sizeof(message1);

	err = she_generate_fast_mac_mubuff_v2(utils_handle, &generate_mac_args);
	if (err) {
		se_err("Error[0x%x]: %s failed.\n", err, __func__);
		return err;
	}

	dump_mac(generate_mac_args.mac, mac1);

	if (memcmp(mac1, generate_mac_args.mac, sizeof(mac1)) != 0) {
		se_print("Generated MAC doesn't match expected MAC [FAIL]\n");
		return SHE_GENERAL_ERROR;
	}

	se_print("SHE GENERATE FAST MAC MUBUFF V2 (16 BYTES) --> PASSED\n");

	memset(&generate_mac_args, 0, sizeof(generate_mac_args));
	generate_mac_args.key_ext = 0x00;
	generate_mac_args.key_id = SHE_KEY_5;
	generate_mac_args.mac = mac;
	generate_mac_args.message = message2;
	generate_mac_args.message_length = sizeof(message2);

	err = she_generate_fast_mac_mubuff_v2(utils_handle, &generate_mac_args);
	if (err) {
		se_err("Error[0x%x]: %s failed.\n", err, __func__);
		return err;
	}

	dump_mac(generate_mac_args.mac, mac2);

	if (memcmp(mac2, generate_mac_args.mac, sizeof(mac2)) != 0) {
		se_print("Generated MAC doesn't match expected MAC [FAIL]\n");
		return SHE_GENERAL_ERROR;
	}

	se_print("SHE GENERATE FAST MAC MUBUFF V2 (40 BYTES) --> PASSED\n");

	memset(&generate_mac_args, 0, sizeof(generate_mac_args));
	generate_mac_args.key_ext = 0;
	generate_mac_args.key_id = SHE_KEY_5;
	generate_mac_args.mac = mac;
	generate_mac_args.message = message3;
	generate_mac_args.message_length = sizeof(message3);

	err = she_generate_fast_mac_mubuff_v2(utils_handle, &generate_mac_args);
	if (err) {
		se_err("Error[0x%x]: %s failed.\n", err, __func__);
		return err;
	}

	dump_mac(generate_mac_args.mac, mac3);

	if (memcmp(mac3, generate_mac_args.mac, sizeof(mac3)) != 0) {
		se_print("Generated MAC doesn't match expected MAC [FAIL]\n");
		return SHE_GENERAL_ERROR;
	}

	se_print("SHE GENERATE FAST MAC MUBUFF V2 (240 BYTES) --> PASSED\n");

	return err;
}

she_err_t do_she_fast_mac_mubuff_v2_test(she_hdl_t utils_handle)
{
	she_err_t err;

	se_print("------ FAST MAC MUBUFF V2 TEST STARTING ------\n");

	err = she_generate_fast_mac_mubuff_v2_test(utils_handle);
	if (err)
		if (err == SHE_FEATURE_NOT_SUPPORTED)
			se_print("GENERATE FAST MAC MUBUFF V2 TEST -> NOT SUPPORTED\n");
		else if (err == SHE_LIB_ERR_IO_BUF_OUT_OF_MEM)
			se_print("MU BUFFER MEMORY EXHAUSTED\n");
		else
			se_print("GENERATE FAST MAC MUBUFF V2 TEST ---> FAILED\n\n");
	else
		se_print("GENERATE FAST MAC MUBUFF V2 TEST ---> PASSED\n\n");

	err = she_verify_fast_mac_mubuff_v2_test(utils_handle);
	if (err)
		if (err == SHE_FEATURE_NOT_SUPPORTED)
			se_print("VERIFY FAST MAC MUBUFF V2 TEST -> NOT SUPPORTED\n");
		else if (err == SHE_LIB_ERR_IO_BUF_OUT_OF_MEM)
			se_print("MU BUFFER MEMORY EXHAUSTED\n");
		else
			se_print("VERIFY FAST MAC MUBUFF V2 TEST ---> FAILED\n\n");
	else
		se_print("VERIFY FAST MAC MUBUFF V2 TEST ---> PASSED\n\n");

	return err;
}
