// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <string.h>
#include "she_api.h"
#include "plat_utils.h"

she_err_t she_verify_mac_test(she_hdl_t utils_handle)
{
	op_verify_mac_t verify_mac_args = {0};
	she_err_t err;
	uint8_t i = 0;
	uint8_t message[SHE_MAC_SIZE] = {0x6b, 0xc1, 0xbe, 0xe2,
					 0x2e, 0x40, 0x9f, 0x96,
					 0xe9, 0x3d, 0x7e, 0x11,
					 0x73, 0x93, 0x17, 0x2a};
	uint8_t input_mac[SHE_MAC_SIZE] = {0x07, 0x0a, 0x16, 0xb4,
					   0x6b, 0x4d, 0x41, 0x44,
					   0xf7, 0x9b, 0xdd, 0x9d,
					   0xd0, 0x4a, 0x28, 0x7c};
	uint8_t message2[40] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
				0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
				0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
				0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
				0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11};
	uint8_t input_mac2[SHE_MAC_SIZE] = {0xdf, 0xa6, 0x67, 0x47,
					    0xde, 0x9a, 0xe6, 0x30,
					    0x30, 0xca, 0x32, 0x61,
					    0x14, 0x97, 0xc8, 0x27};

	verify_mac_args.key_ext = 0x00;
	verify_mac_args.key_id = SHE_KEY_1 | verify_mac_args.key_ext;
	verify_mac_args.mac = input_mac;
	verify_mac_args.mac_length = SHE_MAC_SIZE;
	verify_mac_args.message = message;
	verify_mac_args.message_length = sizeof(message);
	verify_mac_args.mac_length_encoding = MAC_BYTES_LENGTH;

	err = she_verify_mac(utils_handle, &verify_mac_args);
	if (err) {
		se_err("Error[0x%x]: she_verify_mac failed.\n", err);
		return err;
	}

	if (verify_mac_args.verification_status == SHE_MAC_VERIFICATION_SUCCESS) {
		se_print("SHE VERIFY FAST MAC (16 BYTES) --> PASSED\n");
	} else {
		se_print("SHE VERIFY FAST MAC (16 BYTES) --> FAILED\n");
		return SHE_GENERAL_ERROR;
	}

	memset(&verify_mac_args, 0, sizeof(verify_mac_args));
	verify_mac_args.key_ext = 0x00;
	verify_mac_args.key_id = SHE_KEY_1 | verify_mac_args.key_ext;
	verify_mac_args.mac = input_mac2;
	verify_mac_args.mac_length = SHE_MAC_SIZE;
	verify_mac_args.message = message2;
	verify_mac_args.message_length = sizeof(message2);
	verify_mac_args.mac_length_encoding = MAC_BYTES_LENGTH;

	err = she_verify_mac(utils_handle, &verify_mac_args);
	if (err) {
		se_err("Error[0x%x]: she_verify_mac failed.\n", err);
		return err;
	}

	if (verify_mac_args.verification_status == SHE_MAC_VERIFICATION_SUCCESS) {
		se_print("SHE VERIFY FAST MAC (40 BYTES) --> PASSED\n");
	} else {
		se_print("SHE VERIFY FAST MAC (40 BYTES) --> FAILED\n");
		return SHE_GENERAL_ERROR;
	}
	return err;
}

she_err_t she_generate_mac_test(she_hdl_t utils_handle)
{
	op_generate_mac_t generate_mac_args = {0};
	she_err_t err;
	uint8_t i = 0;
	uint8_t mac[SHE_MAC_SIZE] = {0};
	uint8_t message[SHE_MAC_SIZE] = {0x6b, 0xc1, 0xbe, 0xe2,
					 0x2e, 0x40, 0x9f, 0x96,
					 0xe9, 0x3d, 0x7e, 0x11,
					 0x73, 0x93, 0x17, 0x2a};
	uint8_t expected_mac[SHE_MAC_SIZE] = {0x07, 0x0a, 0x16, 0xb4,
					      0x6b, 0x4d, 0x41, 0x44,
					      0xf7, 0x9b, 0xdd, 0x9d,
					      0xd0, 0x4a, 0x28, 0x7c};
	uint8_t message2[40] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
				0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
				0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
				0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
				0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11};
	uint8_t expected_mac2[SHE_MAC_SIZE] = {0xdf, 0xa6, 0x67, 0x47,
					       0xde, 0x9a, 0xe6, 0x30,
					       0x30, 0xca, 0x32, 0x61,
					       0x14, 0x97, 0xc8, 0x27};

	generate_mac_args.key_ext = 0x00;
	generate_mac_args.key_id = SHE_KEY_5 | generate_mac_args.key_ext;
	generate_mac_args.mac = mac;
	generate_mac_args.message = message;
	generate_mac_args.message_length = sizeof(message);

	err = she_generate_mac(utils_handle, &generate_mac_args);
	if (err) {
		se_err("Error[0x%x]: she_generate_mac failed.\n", err);
		return err;
	}

	for (i = 0; i < SHE_MAC_SIZE; i++) {
		if ((i % 10) == 0)
			printf("\n");
		printf("%02x:%02x ", generate_mac_args.mac[i], expected_mac[i]);
	}
	printf("\n");

	if (memcmp(expected_mac, generate_mac_args.mac, sizeof(expected_mac)) != 0) {
		se_print("Generated MAC doesn't match expected MAC [FAIL]\n");
		return err;
	}

	se_print("SHE GENERATE FAST MAC (16 BYTES) --> PASSED\n");

	memset(&generate_mac_args, 0, sizeof(generate_mac_args));
	generate_mac_args.key_ext = 0x00;
	generate_mac_args.key_id = SHE_KEY_5 | generate_mac_args.key_ext;
	generate_mac_args.mac = mac;
	generate_mac_args.message = message2;
	generate_mac_args.message_length = sizeof(message2);

	err = she_generate_mac(utils_handle, &generate_mac_args);
	if (err) {
		se_err("Error[0x%x]: she_generate_mac failed.\n", err);
		return err;
	}

	for (i = 0; i < SHE_MAC_SIZE; i++) {
		if ((i % 10) == 0)
			printf("\n");
		printf("%02x:%02x ", generate_mac_args.mac[i], expected_mac2[i]);
	}
	printf("\n");

	if (memcmp(expected_mac2, generate_mac_args.mac, sizeof(expected_mac2)) != 0) {
		se_print("Generated MAC doesn't match expected MAC [FAIL]\n");
		return err;
	}

	se_print("SHE GENERATE FAST MAC (40 BYTES) --> PASSED\n");
	return err;
}

she_err_t do_she_fast_mac_test(she_hdl_t utils_handle)
{
	she_err_t err;

	se_print("------ FAST MAC TEST STARTING ------\n");
	err = she_generate_mac_test(utils_handle);
	if (err)
		se_print("GENERATE FAST MAC TEST ---> FAILED\n\n");
	else
		se_print("GENERATE FAST MAC TEST ---> PASSED\n\n");

	err = she_verify_mac_test(utils_handle);
	if (err)
		se_print("VERIFY FAST MAC TEST ---> FAILED\n\n");
	else
		se_print("VERIFY FAST MAC TEST ---> PASSED\n\n");

	return err;
}
