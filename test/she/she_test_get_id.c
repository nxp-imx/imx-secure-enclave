// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <string.h>
#include "she_api.h"
#include "plat_utils.h"

she_err_t she_get_id_test(she_hdl_t utils_handle)
{
	op_get_id_args_t get_id_args = {0};
	she_err_t err;
	uint8_t i = 0;
	uint8_t challenge[SHE_CHALLENGE_SIZE] = {0x40, 0xab, 0xde, 0xab,
						 0x16, 0xde, 0x77, 0xb9,
						 0x59, 0x99, 0x64, 0xb3,
						 0xd2, 0xdd, 0x72, 0x61};
	uint8_t mac[SHE_MAC_SIZE] = {0};
	uint8_t id[SHE_ID_SIZE] = {0};
	uint8_t challenge2[SHE_CHALLENGE_SIZE] = {0x6b, 0xc1, 0xbe, 0xe2,
						  0x2e, 0x40, 0x9f, 0x96,
						  0xe9, 0x3d, 0x7e, 0x11,
						  0x73, 0x93, 0x17, 0x2a};

	memcpy(get_id_args.mac, mac, SHE_MAC_SIZE);
	memcpy(get_id_args.challenge, challenge, SHE_CHALLENGE_SIZE);
	memcpy(get_id_args.id, id, SHE_ID_SIZE);

	err = she_get_id(utils_handle, &get_id_args);
	if (err) {
		se_err("Error[0x%x]: she_get_id failed.\n", err);
		return err;
	}

	se_print("MAC:");
	for (i = 0; i < SHE_MAC_SIZE; i++) {
		if ((i % 10) == 0)
			printf("\n");
		printf("%02x ", get_id_args.mac[i]);
	}
	printf("\n");

	se_print("UID:");
	for (i = 0; i < SHE_ID_SIZE; i++) {
		if ((i % 10) == 0)
			printf("\n");
		printf("%02x ", get_id_args.id[i]);
	}
	printf("\n");

	se_print("status register: 0x%x\n", get_id_args.sreg);

	memset(&get_id_args, 0, sizeof(get_id_args));
	memset(mac, 0, sizeof(mac));
	memset(id, 0, sizeof(id));
	memcpy(get_id_args.mac, mac, SHE_MAC_SIZE);
	memcpy(get_id_args.challenge, challenge2, SHE_CHALLENGE_SIZE);
	memcpy(get_id_args.id, id, SHE_ID_SIZE);

	err = she_get_id(utils_handle, &get_id_args);
	if (err) {
		se_err("Error[0x%x]: she_get_id failed.\n", err);
		return err;
	}

	se_print("Test 2:\nMAC:");
	for (i = 0; i < SHE_MAC_SIZE; i++) {
		if ((i % 10) == 0)
			printf("\n");
		printf("%02x ", get_id_args.mac[i]);
	}
	printf("\n");

	se_print("UID:");
	for (i = 0; i < SHE_ID_SIZE; i++) {
		if ((i % 10) == 0)
			printf("\n");
		printf("%02x ", get_id_args.id[i]);
	}
	printf("\n");

	se_print("status register: 0x%x\n", get_id_args.sreg);

	return err;
}

she_err_t do_she_get_id_test(she_hdl_t utils_handle)
{
	she_err_t err;

	err = she_get_id_test(utils_handle);
	if (err)
		se_print("GET ID TEST ---> FAILED\n\n");
	else
		se_print("GET ID TEST ---> PASSED\n\n");

	return err;
}
