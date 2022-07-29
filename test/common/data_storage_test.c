/*
 * Copyright 2022 NXP
 *
 * NXP Confidential.
 * This software is owned or controlled by NXP and may only be used strictly
 * in accordance with the applicable license terms.  By expressly accepting
 * such terms or by downloading, installing, activating and/or otherwise using
 * the software, you are agreeing that you have read, and that you agree to
 * comply with and are bound by, such license terms.  If you do not agree to be
 * bound by the applicable license terms, then you may not retain, install,
 * activate or otherwise use the software.
 */

#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "hsm_api.h"
#include "common.h"
#include "nvm.h"

#define DATA_ID			0x01

#define LINE_SIZE		12
#define LAST_IDX_IN_A_LINE	(LINE_SIZE - 1)
#define LOG_LEVEL		1

static void test_status(uint8_t *input, uint8_t *output, int len, char *result_str)
{
	int j;

	printf("Test Output for %s:\n", result_str);
#if (LOG_LEVEL > 0)
	for (j = 0; j < len; j++) {
		printf("0x%02x, ", output[j]);
		if (j % LINE_SIZE == 15)
			printf("\n");
	}
#endif
	if (memcmp(output, input, len) == 0) {
		printf("Result --> SUCCESS\n");
	} else {
		printf("Result --> FAILURE\n");
	}
}

static uint8_t  test_data[300] = {
	/* Note that the first 32 Bytes are the "Z" value
	 * that can be retrieved with hsm_sm2_get_z()
	 */
	0xB2, 0xE1, 0x4C, 0x5C, 0x79, 0xC6, 0xDF, 0x5B, 0x85, 0xF4, 0xFE, 0x7E,
	0xD8, 0xDB, 0x7A, 0x26,	0x2B, 0x9D, 0xA7, 0xE0, 0x7C, 0xCB, 0x0E, 0xA9,
	0xF4, 0x74, 0x7B, 0x8C, 0xCD, 0xA8, 0xA4, 0xF3, 0x6D, 0x65, 0x73, 0x73,
	0x61, 0x67, 0x65, 0x20, 0xB2, 0xE1, 0x4C, 0x5C, 0x79, 0xC6, 0xDF, 0x5B,
	0x85, 0xF4, 0xFE, 0x7E, 0xD8, 0xDB, 0x7A, 0x26, 0x2B, 0x9D, 0xA7, 0xE0,
	0x7C, 0xCB, 0x0E, 0xA9,	0xF4, 0x74, 0x7B, 0x8C, 0xCD, 0xA8, 0xA4, 0xF3,
	0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20,	0xB2, 0xE1, 0x4C, 0x5C,
	0x79, 0xC6, 0xDF, 0x5B, 0x85, 0xF4, 0xFE, 0x7E, 0xD8, 0xDB, 0x7A, 0x26,
	0x2B, 0x9D, 0xA7, 0xE0, 0x7C, 0xCB, 0x0E, 0xA9, 0xF4, 0x74, 0x7B, 0x8C,
	0xCD, 0xA8, 0xA4, 0xF3,	0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20,
	0xB2, 0xE1, 0x4C, 0x5C, 0x79, 0xC6, 0xDF, 0x5B, 0x85, 0xF4, 0xFE, 0x7E,
	0xD8, 0xDB, 0x7A, 0x26, 0x2B, 0x9D, 0xA7, 0xE0, 0x7C, 0xCB, 0x0E, 0xA9,
	0xF4, 0x74, 0x7B, 0x8C, 0xCD, 0xA8, 0xA4, 0xF3, 0x6D, 0x65, 0x73, 0x73,
	0x61, 0x67, 0x65, 0x20,	0xB2, 0xE1, 0x4C, 0x5C, 0x79, 0xC6, 0xDF, 0x5B,
	0x85, 0xF4, 0xFE, 0x7E, 0xD8, 0xDB, 0x7A, 0x26,	0x2B, 0x9D, 0xA7, 0xE0,
	0x7C, 0xCB, 0x0E, 0xA9, 0xF4, 0x74, 0x7B, 0x8C, 0xCD, 0xA8, 0xA4, 0xF3,
	0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0xB2, 0xE1, 0x4C, 0x5C,
	0x79, 0xC6, 0xDF, 0x5B,	0x85, 0xF4, 0xFE, 0x7E, 0xD8, 0xDB, 0x7A, 0x26,
	0x2B, 0x9D, 0xA7, 0xE0, 0x7C, 0xCB, 0x0E, 0xA9,	0xF4, 0x74, 0x7B, 0x8C,
	0xCD, 0xA8, 0xA4, 0xF3, 0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20,
	0xB2, 0xE1, 0x4C, 0x5C, 0x79, 0xC6, 0xDF, 0x5B, 0x85, 0xF4, 0xFE, 0x7E,
	0xD8, 0xDB, 0x7A, 0x26,	0x2B, 0x9D, 0xA7, 0xE0, 0x7C, 0xCB, 0x0E, 0xA9,
	0xF4, 0x74, 0x7B, 0x8C, 0xCD, 0xA8, 0xA4, 0xF3,	0x6D, 0x65, 0x73, 0x73,
	0x61, 0x67, 0x65, 0x20, 0xB2, 0xE1, 0x4C, 0x5C, 0x79, 0xC6, 0xDF, 0x5B,
	0x85, 0xF4, 0xFE, 0x7E, 0xD8, 0xDB, 0x7A, 0x26, 0x2B, 0x9D, 0xA7, 0xE0,
};

uint8_t recieved_data[300];

void data_storage_test(hsm_hdl_t key_store_hdl, int arg)
{
	hsm_hdl_t data_storage_hdl;
	op_data_storage_args_t data_storage_args;
	hsm_err_t err;
	int j;
	uint32_t size = arg ? arg : sizeof(test_data);

#ifdef SECONDARY_API_SUPPORTED
	printf("\n---------------------------------------------------\n");
	printf(" Secondary API Test: Data Storage Test\n");
	printf("---------------------------------------------------\n");

	data_storage_args.svc_flags = 0;
	data_storage_args.data = test_data;
	data_storage_args.data_size = size;
	data_storage_args.data_id = DATA_ID;
	data_storage_args.flags |= HSM_OP_DATA_STORAGE_FLAGS_STORE;
	err = hsm_data_ops(key_store_hdl, &data_storage_args);
	if (err) {
		printf("Err[Store]: 0x%x hsm_data_ops.\n", err);
		dump_firmware_log(get_hsm_session_hdl());
		return;
	}

	memset(&data_storage_args, 0, sizeof(op_data_storage_args_t));
	data_storage_args.svc_flags = 0;
	data_storage_args.data = recieved_data;
	data_storage_args.data_size = size;
	data_storage_args.data_id = DATA_ID;
	data_storage_args.flags |= HSM_OP_DATA_STORAGE_FLAGS_RETRIEVE;
	err = hsm_data_ops(key_store_hdl, &data_storage_args);
	if (err) {
		printf("Err[Re-Store]: 0x%x hsm_data_ops.\n", err);
		dump_firmware_log(get_hsm_session_hdl());
		return;
	}

#else
	printf("\n---------------------------------------------------\n");
	printf("Data Storage Test\n");
	printf("---------------------------------------------------\n");

	open_svc_data_storage_args_t args = {0};

	err = hsm_open_data_storage_service(key_store_hdl, &args,
			&data_storage_hdl);

	if (err) {
		printf("err: 0x%x hsm_open_data_storage_service hdl: 0x%08x\n",
				err, data_storage_hdl);
		return;
	}

	data_storage_args.data = test_data;
	data_storage_args.data_size = size;
	data_storage_args.data_id = DATA_ID;
	data_storage_args.flags |= HSM_OP_DATA_STORAGE_FLAGS_STORE;
	err = hsm_data_storage(data_storage_hdl, &data_storage_args);
	if (err) {
		printf("Err[Store]: 0x%x hsm_data_storage hdl: 0x%08x\n",
							err, data_storage_hdl);
		dump_firmware_log(get_hsm_session_hdl());
		return;
	}

	memset(&data_storage_args, 0, sizeof(op_data_storage_args_t));

	data_storage_args.flags = 0;
	data_storage_args.data = recieved_data;
	data_storage_args.data_size = size;
	data_storage_args.data_id = DATA_ID;
	data_storage_args.flags |= HSM_OP_DATA_STORAGE_FLAGS_RETRIEVE;
	err = hsm_data_storage(data_storage_hdl, &data_storage_args);
	if (err) {
		printf("Err[Re-Store]: 0x%x hsm_data_storage hdl: 0x%08x\n",
							err, data_storage_hdl);
		dump_firmware_log(get_hsm_session_hdl());
		return;
	}

	test_status(test_data, recieved_data, size,
			"SAB_DATA_STORAGE_REQ");

	err = hsm_close_data_storage_service(data_storage_hdl);
	if (err) {
		printf("err: 0x%x hsm_close_data_storage_service hdl: 0x%08x\n",
				err, data_storage_hdl);
		return;
	}
#endif
	test_status(test_data, recieved_data, size,
			"SAB_DATA_STORAGE_REQ");
	printf("---------------------------------------------------\n");
}
