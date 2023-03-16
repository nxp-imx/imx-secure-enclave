/*
 * Copyright 2022-2023 NXP
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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hsm_api.h"
#include "test_common_tv.h"
#include "test_utils_tv.h"

#define DELETE 1

#define MAX_KEY_MGMT_SRV_N 4
#define MAX_TV_KEY_ID 30

uint8_t active_key_mgmt_srv_ctr;
uint8_t active_keys_ctr;

struct key_mgmt_tv_id_map key_mgmt_id_map_arr[MAX_KEY_MGMT_SRV_N];
struct key_tv_id_map key_tv_id_map_arr[MAX_TV_KEY_ID];

/* To be used by Test Vector file tests to parse numerical value for its
 * parameter from given token
 */
uint32_t parse_param_value(char *param_value_token, char *param_name,
						uint8_t *input_ctr, uint8_t *invalid_read)
{
	uint32_t param_value = 0;
	char *check_invalid = NULL;

	param_value = (uint32_t)strtoul(param_value_token, &check_invalid, 0);

	if (param_value_token == check_invalid) {
		printf("\nError: Invalid read for %s\n", param_name);
		*invalid_read = 1;
	} else {
		++(*input_ctr);
	}

	return param_value;
}

/* To parse input buffers provided in test vector file as test inputs */
void parse_param_value_buffer(FILE *fp, uint8_t **dst, uint32_t size,
							char *param_name, uint8_t *input_ctr,
							uint8_t *invalid_read)
{
	char *line = NULL;
	char *startptr = NULL;
	char *endptr = NULL;
	uint8_t *dst_ptr = NULL;
	size_t len = 0;
	ssize_t read;
	uint32_t i = 0;
	uint32_t data = 0;

	if (size == 0) {
		++(*input_ctr);
		return;
	}

	while (i < size) {
		read = getline(&line, &len, fp);

		if (read < 0)
			break;

		dst_ptr = *dst;

		startptr = line;
		data = strtoul(startptr, &endptr, 0);

		while (endptr != startptr) {
			dst_ptr[i++] = (uint8_t)(data & 0xFFu);
			startptr = endptr + 1; /* skip separator of buffer values */
			data = strtoul(startptr, &endptr, 0);
		}
	}

	if (i != size) {
		printf("\nError: Invalid read for %s\n", param_name);
		*invalid_read = 1;
	} else {
		++(*input_ctr);
	}

	free(line);
}

/* Print test vector file input/output buffers */
void print_buffer(uint8_t *buffer_ptr, uint32_t size)
{
	printf("[");

	for (uint32_t i = 0; i < size; i++) {

		if ((i+1)%10 == 0)
			printf("\n");

		printf("0x%02x, ", buffer_ptr[i]);
	}

	printf("]\n\n");
}

/* Save generated keys from tests TEST_KGEN_* */
void save_test_key(uint32_t key_tv_id, uint32_t key_identifier,
				uint32_t key_mgmt_tv_id, hsm_key_group_t key_group,
				hsm_key_type_t key_type)
{
	uint8_t flag = 0;

	if (active_keys_ctr >= MAX_TV_KEY_ID) {
		printf("\nFailed: Not Saving any more keys. MAX limit is reached\n");
		return;
	}

	if (key_tv_id == 0) {
		printf("\nFailed: KEY_TV_ID must be non-zero positive value\n");
		return;
	}

	for (uint8_t i = 0; i < MAX_TV_KEY_ID; i++) {
		if (key_tv_id_map_arr[i].key_tv_id == key_tv_id) {
			flag = 1;
			break;
		}
	}

	if (flag == 0) {
		//Save new Key details on the first empty slot of array
		for (uint8_t i = 0; i < MAX_TV_KEY_ID; i++) {
			if (key_tv_id_map_arr[i].key_tv_id == 0) {
				key_tv_id_map_arr[i].key_tv_id = key_tv_id;
				key_tv_id_map_arr[i].key_identifier = key_identifier;
				key_tv_id_map_arr[i].key_mgmt_tv_id = key_mgmt_tv_id;
				key_tv_id_map_arr[i].key_group = key_group;
				key_tv_id_map_arr[i].key_type = key_type;
				++active_keys_ctr;
				break;
			}
		}
	} else {
		printf("\nFailed: KEY_TV_ID key already Exists\n");
	}
}

/* Save Persistent Key detail in a file */
void save_persistent_key(uint32_t key_tv_id, uint32_t key_identifier)
{
	FILE *fp = NULL;
	char create_persist_key_path[128];
	int8_t ret = -1;

	snprintf(create_persist_key_path, sizeof(create_persist_key_path),
		 "mkdir -p %s", DEFAULT_TV_PKF_PATH);
	ret = system(create_persist_key_path);

	fp = fopen(DEFAULT_TV_PKF_FPATH, "a");

	if (!fp) {
		printf("\nERROR: Failed to open %s.\n\n", DEFAULT_TV_PKF_FPATH);
		return;
	}

	fprintf(fp, "%u 0x%x\n", key_tv_id, key_identifier);
	printf("\nPersistent Key Identifier 0x%x entered in file\n", key_identifier);
}

/* Load persistent keys details */
void load_persist_key_info(void)
{
	char *line = NULL;
	size_t len = 0;
	FILE *fp = NULL;
	char *key_tv_id_str = NULL;
	char *key_identifier_str = NULL;
	char *temp = NULL;
	char *check_invalid = NULL;
	ssize_t read = 0;

	uint32_t key_tv_id = 0;
	uint32_t key_identifier = 0;

	fp = fopen(DEFAULT_TV_PKF_FPATH, "r");

	if (!fp) {
		printf("\nERROR: Failed to open %s.\n\n", DEFAULT_TV_PKF_FPATH);
		return;
	}

	while ((read = getline(&line, &len, fp)) != -1) {
		key_tv_id_str = strtok_r(line, " ", &temp);

		if (!key_tv_id_str) {
			continue;
		} else {
			key_identifier_str = strtok_r(NULL, " ", &temp);

			if (!key_identifier_str)
				continue;
		}

		key_tv_id = (uint32_t)strtoul(key_tv_id_str, &check_invalid, 0);

		if (key_tv_id_str == check_invalid) {
			printf("\nError: Invalid read for KEY_TV_ID while loading...\n");
			continue;
		}

		key_identifier = (uint32_t)strtoul(key_identifier_str, &check_invalid, 0);

		if (key_identifier_str == check_invalid) {
			printf("\nError: Invalid read for KEY_IDENTIFIER while loading...\n");
			continue;
		}

		save_test_key(key_tv_id, key_identifier, 0, 0, 0);
		printf("\nPersistent Key Info Loaded: KEY_TV_ID %u  Key Identifier 0x%x\n",
		       key_tv_id, key_identifier);
	}
}

/* Get key identifier from key_tv_id */
uint32_t get_test_key_identifier(uint32_t key_tv_id)
{
	uint32_t key_identifier = 0;
	uint8_t flag = 0;
	uint8_t i = 0;

	for (i = 0; i < MAX_TV_KEY_ID; i++) {
		if (key_tv_id_map_arr[i].key_tv_id == key_tv_id) {
			flag = 1;
			break;
		}
	}

	if (flag == 0)
		printf("\nNo Existing Key Identifier for given KEY_TV_ID\n");
	else
		key_identifier = key_tv_id_map_arr[i].key_identifier;

	return key_identifier;
}

/* Delete the key after use */
void delete_test_key(uint32_t key_tv_id)
{
	uint8_t flag = 0;
	uint8_t i = 0;

	if (active_keys_ctr <= 0) {
		printf("\nNo Keys available to delete\n");
		return;
	}

	for (i = 0; i < MAX_TV_KEY_ID; i++) {
		if (key_tv_id_map_arr[i].key_tv_id == key_tv_id) {
			flag = 1;
			break;
		}
	}

	if (flag == 0) {

		printf("\nNo key Match found for given TEST KEY TV ID\n");

	} else {

		uint32_t key_mgmt_hdl = get_key_mgmt_hdl(key_tv_id_map_arr[i].key_mgmt_tv_id);

		printf("\nDELETE KEY - [KEY_TV_ID: %u, KEY_MGMT_TV_ID: %u, KEY GROUP: %u]\n",
				key_tv_id_map_arr[i].key_tv_id,
				key_tv_id_map_arr[i].key_mgmt_tv_id,
				key_tv_id_map_arr[i].key_group);

		key_management(DELETE,
						key_mgmt_hdl,
						&key_tv_id_map_arr[i].key_identifier,
						key_tv_id_map_arr[i].key_group,
						key_tv_id_map_arr[i].key_type);

		//cleanup after deletion of the saved keys
		key_tv_id_map_arr[i].key_tv_id = 0;
		key_tv_id_map_arr[i].key_mgmt_tv_id = 0;
		key_tv_id_map_arr[i].key_identifier = 0;
		key_tv_id_map_arr[i].key_group = 0;
		key_tv_id_map_arr[i].key_type = 0;
		--active_keys_ctr;
	}
}

/* Open Key mgmt service and add in array */
hsm_hdl_t open_key_mgmt_srv(hsm_hdl_t key_store_hdl, uint32_t key_mgmt_tv_id)
{
	hsm_err_t ret = HSM_GENERAL_ERROR;
	hsm_hdl_t key_mgmt_hdl = 0;
	open_svc_key_management_args_t key_mgmt_args;
	uint8_t flag = 0;

	memset(&key_mgmt_args, 0, sizeof(key_mgmt_args));

	if (key_mgmt_tv_id == 0) {
		printf("\nIncorrect KEY_MGMT_TV_ID. It must be non-zero.\n");
		return key_mgmt_hdl;
	}

	if (active_key_mgmt_srv_ctr >= MAX_KEY_MGMT_SRV_N) {
		printf("\nMax Number of Key Management services are already opened.\n");
		return key_mgmt_hdl;
	}

	/* Check if Key Mgmt service already open for given KEY_MGMT_TV_ID */
	for (uint8_t i = 0; i < MAX_KEY_MGMT_SRV_N; i++) {
		if (key_mgmt_id_map_arr[i].key_mgmt_tv_id == key_mgmt_tv_id) {
			flag = 1;
			break;
		}
	}

	if (flag == 0) {

		/* Start and add Key Mgmt service for provided KEY_MGMT_TV_ID */
		for (uint8_t i = 0; i < MAX_KEY_MGMT_SRV_N; i++) {
			if (key_mgmt_id_map_arr[i].key_mgmt_tv_id == 0) {

				key_mgmt_id_map_arr[i].key_mgmt_tv_id = key_mgmt_tv_id;

				ret = hsm_open_key_management_service(key_store_hdl,
					&key_mgmt_args, &key_mgmt_id_map_arr[i].key_mgmt_hdl);

				if (ret == HSM_NO_ERROR) {
					++active_key_mgmt_srv_ctr;
					key_mgmt_hdl = key_mgmt_id_map_arr[i].key_mgmt_hdl;
				}

				printf("\nhsm_open_key_management_service() ret: 0x%x [KEY_MGMT_TV_ID: %u]\n", ret, key_mgmt_tv_id);
				break;
			}
		}

	} else {
		key_mgmt_hdl = get_key_mgmt_hdl(key_mgmt_tv_id);
	}

	return key_mgmt_hdl;
}

hsm_hdl_t get_key_mgmt_hdl(uint32_t key_mgmt_tv_id)
{
	hsm_hdl_t key_mgmt_hdl = 0;
	uint32_t flag = 0;
	uint8_t i = 0;

	for (i = 0; i < MAX_KEY_MGMT_SRV_N; i++) {
		if (key_mgmt_id_map_arr[i].key_mgmt_tv_id == key_mgmt_tv_id) {
			flag = 1;
			break;
		}
	}

	if (flag == 1)
		key_mgmt_hdl = key_mgmt_id_map_arr[i].key_mgmt_hdl;
	else
		printf("\nFailed: No valid Key Mgmt handle Exists for given KEY_MGMT_TV_ID\n");

	return key_mgmt_hdl;
}

void close_key_mgmt_srv(uint32_t key_mgmt_tv_id)
{
	hsm_err_t ret = HSM_GENERAL_ERROR;
	hsm_hdl_t key_mgmt_hdl = 0;

	if (active_key_mgmt_srv_ctr <= 0) {
		printf("\nNo active Key Management services\n");
		return;
	}

	key_mgmt_hdl = get_key_mgmt_hdl(key_mgmt_tv_id);

	if (key_mgmt_hdl != 0) {

		//Delete saved test Keys under this Key Mgmt service before closing it
		for (uint8_t i = 0; i < MAX_TV_KEY_ID; i++) {
			if (key_tv_id_map_arr[i].key_tv_id != 0 &&
				key_tv_id_map_arr[i].key_mgmt_tv_id == key_mgmt_tv_id) {
				delete_test_key(key_tv_id_map_arr[i].key_tv_id);
			}
		}

		ret = hsm_close_key_management_service(key_mgmt_hdl);
		printf("\n\nhsm_close_key_management_service() ret: 0x%x [KEY_MGMT_TV_ID: %u]\n", ret, key_mgmt_tv_id);
	}

	if (ret == HSM_NO_ERROR) {
		//Clean array slot for this Key Mgmt service
		for (uint8_t i = 0; i < MAX_KEY_MGMT_SRV_N; i++) {
			if (key_mgmt_id_map_arr[i].key_mgmt_tv_id == key_mgmt_tv_id) {
				key_mgmt_id_map_arr[i].key_mgmt_tv_id = 0;
				key_mgmt_id_map_arr[i].key_mgmt_hdl = 0;
				--active_key_mgmt_srv_ctr;
				break;
			}
		}
	}
}
