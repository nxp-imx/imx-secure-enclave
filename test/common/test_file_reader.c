// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "test_common_tv.h"

/* To run tests in Test Vector file */
void tv_tests_run(hsm_hdl_t key_store_hdl, uint8_t *tv_file_path)
{
	uint32_t key_mgmt_tv_id = 0;

	char *line = NULL;
	char *check_invalid = NULL;
	size_t len = 0;
	FILE *fp = NULL;
	ssize_t read;

	// open default test vector file as custom tv file path not provided.
	if (tv_file_path == NULL)
		tv_file_path = DEFAULT_TV_FPATH;

	fp = fopen(tv_file_path, "r");

	printf("\n\nTest Vector file: %s\n", tv_file_path);

	if (fp == NULL) {
		printf("\nERROR: Failed to open %s.\n\n", tv_file_path);
		return;
	}

	printf("\n\n------------------------------\n");
	printf("TEST VECTORS: TESTS STARTED");
	printf("\n------------------------------\n");

	while ((read = getline(&line, &len, fp)) != -1) {

		if (memcmp(line, "TESTS_START", 11) == 0) {

			printf("\n\nTESTS START\n\n");

			while ((read = getline(&line, &len, fp)) != -1) {

				if (memcmp(line, "TESTS_END", 9) == 0) {
					printf("\n\nTESTS ENDED\n\n");
					break;
				}

				/* Open Key Management service */
				if (memcmp(line, "OPEN_KEY_MGMT_SRV", 17) == 0) {

					/* Read the next line for KEY_MGMT_TV_ID value */
					read = getline(&line, &len, fp);

					key_mgmt_tv_id = (uint32_t)strtoul(line, &check_invalid, 0);

					if (line != check_invalid) {
						open_key_mgmt_srv(key_store_hdl, key_mgmt_tv_id);
					} else {
						printf("\nInvalid read - Key Mgmt ID value [OPEN_KEY_MGMT_SRV]\n");
						check_invalid = NULL;
						break;
					}
				}

				/* Key Generation tests */
				if (memcmp(line, "TEST_KGEN", 9) == 0)
					generate_key_test_tv(key_store_hdl, fp, line);

				/* Cipher tests */
				if (memcmp(line, "TEST_CIPHER", 11) == 0)
					cipher_test_tv(key_store_hdl, fp, line);

				/* MAC tests */
				if (memcmp(line, "TEST_MAC", 8) == 0)
					mac_test_tv(key_store_hdl, fp, line);


				/* Signature Generation and Verification tests */
				if (memcmp(line, "TEST_SIGN_VERIFY", 16) == 0)
					sign_verify_test_tv(key_store_hdl, fp, line);


				/* Hash tests */
				if (memcmp(line, "TEST_HASH", 9) == 0)
					hash_test_tv(fp, line);

				/* Data Storage tests*/
				if (memcmp(line, "TEST_DATA_STORAGE", 17) == 0)
					data_storage_test_tv(key_store_hdl, fp, line);

				/* Load Peristent Key Details */
				if (memcmp(line, "LOAD_PERSIST_KEY_INFO", 21) == 0)
					load_persist_key_info();

				/*
				 * Add other tests such as RNG etc. later
				 */


				/* Close Key management service */
				if (memcmp(line, "CLOSE_KEY_MGMT_SRV", 18) == 0) {

					/* Read the next line for KEY_MGMT_TV_ID value */
					read = getline(&line, &len, fp);

					key_mgmt_tv_id = (uint32_t)strtoul(line, &check_invalid, 0);

					if (line != check_invalid) {
						close_key_mgmt_srv(key_mgmt_tv_id);
					} else {
						printf("\nInvalid read - Key Mgmt ID value [CLOSE_KEY_MGMT_SRV]\n");
						check_invalid = NULL;
						break;
					}
				}
			}

		}
	}

	printf("\n------------------------------\n");
	printf("TEST VECTORS: TESTS ENDED");
	printf("\n------------------------------\n\n");

	free(line);
	fclose(fp);
}
