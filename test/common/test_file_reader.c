// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2024 NXP
 */

#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>

#include "test_common_tv.h"
#include "plat_utils.h"

// Run tests of selected Test Vector file
static void tv_tests(hsm_hdl_t key_store_hdl, uint8_t *tv_file_path)
{
	uint32_t key_mgmt_tv_id = 0;
	uint16_t tkgen_passed = 0;
	uint16_t tkgen_failed = 0;
	uint16_t tkgen_invalid = 0;
	uint16_t tkgen_total = 0;
	uint16_t tcipher_passed = 0;
	uint16_t tcipher_failed = 0;
	uint16_t tcipher_invalid = 0;
	uint16_t tcipher_total = 0;
	uint16_t tmac_passed = 0;
	uint16_t tmac_failed = 0;
	uint16_t tmac_invalid = 0;
	uint16_t tmac_total = 0;
	uint16_t tsign_passed = 0;
	uint16_t tsign_failed = 0;
	uint16_t tsign_invalid = 0;
	uint16_t tsign_total = 0;
	uint16_t thash_passed = 0;
	uint16_t thash_failed = 0;
	uint16_t thash_invalid = 0;
	uint16_t thash_total = 0;
	uint16_t tdata_passed = 0;
	uint16_t tdata_failed = 0;
	uint16_t tdata_invalid = 0;
	uint16_t tdata_total = 0;

	char *line = NULL;
	char *check_invalid = NULL;
	size_t len = 0;
	FILE *fp = NULL;
	ssize_t read;

	fp = fopen(tv_file_path, "r");

	printf("\n\nTest Vector file: %s\n", tv_file_path);

	if (!fp) {
		printf("\nERROR: Failed to open %s.\n\n", tv_file_path);
		return;
	}

	printf("\n\n------------------------------\n");
	printf("TEST VECTORS: TESTS STARTED");
	printf("\n------------------------------\n");

	while ((read = getline(&line, &len, fp)) != -1) {

		if (memcmp(line, "TESTS_START", 11) == 0) {

			se_info("\n\nTESTS START\n\n");

			while ((read = getline(&line, &len, fp)) != -1) {

				if (memcmp(line, "TESTS_END", 9) == 0) {
					se_info("\n\nTESTS ENDED\n\n");
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
					generate_key_test_tv(key_store_hdl, fp,
							     line, &tkgen_passed,
							     &tkgen_failed,
							     &tkgen_invalid,
							     &tkgen_total);

				/* Cipher tests */
				if (memcmp(line, "TEST_CIPHER", 11) == 0)
					cipher_test_tv(key_store_hdl, fp, line,
						       &tcipher_passed, &tcipher_failed,
						       &tcipher_invalid,
						       &tcipher_total);

				/* MAC tests */
				if (memcmp(line, "TEST_MAC", 8) == 0)
					mac_test_tv(key_store_hdl, fp, line,
						    &tmac_passed, &tmac_failed,
						    &tmac_invalid, &tmac_total);


				/* Signature Generation and Verification tests */
				if (memcmp(line, "TEST_SIGN_VERIFY", 16) == 0)
					sign_verify_test_tv(key_store_hdl, fp,
							    line, &tsign_passed,
							    &tsign_failed,
							    &tsign_invalid,
							    &tsign_total);
#ifndef ELE_PERF
				/* Hash tests */
				if (memcmp(line, "TEST_HASH", 9) == 0)
					hash_test_tv(fp, line, &thash_passed,
						     &thash_failed,
						     &thash_invalid, &thash_total);

				/* Data Storage tests*/
				if (memcmp(line, "TEST_DATA_STORAGE", 17) == 0)
					data_storage_test_tv(key_store_hdl, fp,
							     line, &tdata_passed,
							     &tdata_failed,
							     &tdata_invalid,
							     &tdata_total);
#endif
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

	if (tkgen_total > 0) {
		printf("TESTS REPORT KGEN:: TOTAL: %u, SUCCESS: %u, FAILED: %u, INVALID: %u",
		       tkgen_total, tkgen_passed, tkgen_failed, tkgen_invalid);
		printf("\n----------------------------------------------------------\n\n");
	}

	if (tcipher_total > 0) {
		printf("TESTS REPORT CIPHER:: TOTAL: %u, SUCCESS: %u, FAILED: %u, INVALID: %u",
		       tcipher_total, tcipher_passed, tcipher_failed, tcipher_invalid);
		printf("\n--------------------------------------------------------------\n\n");
	}

	if (tmac_total > 0) {
		printf("TESTS REPORT MAC:: TOTAL: %u, SUCCESS: %u, FAILED: %u, INVALID: %u",
		       tmac_total, tmac_passed, tmac_failed, tmac_invalid);
		printf("\n-----------------------------------------------------------\n\n");
	}

	if (tsign_total > 0) {
		printf("TESTS REPORT SIGN VERIFY:: TOTAL: %u, SUCCESS: %u, FAILED: %u, INVALID: %u",
		       tsign_total, tsign_passed, tsign_failed, tsign_invalid);
		printf("\n-------------------------------------------------------------------\n\n");
		}

	if (thash_total > 0) {
		printf("TESTS REPORT HASH:: TOTAL: %u, SUCCESS: %u, FAILED: %u, INVALID: %u",
		       thash_total, thash_passed, thash_failed, thash_invalid);
		printf("\n------------------------------------------------------------\n\n");
	}

	if (tdata_total > 0) {
		printf("TESTS REPORT DATA STORAGE: TOTAL: %u, SUCCESS: %u, FAILED: %u, INVALID: %u",
		       tdata_total, tdata_passed, tdata_failed, tdata_invalid);
		printf("\n-----------------------------------------------------------------\n\n");
	}

	if (line)
		free(line);

	if (fp)
		fclose(fp);
}

// return 0 if file extension matches expected extension
static uint32_t extn_match(char *fname, char *exp_extn)
{
	char *file_extn = strrchr(fname, '.');

	if (file_extn == fname || !file_extn)
		return 1;

	// compare file extensions
	if (strcmp(file_extn, exp_extn) == 0)
		return 0;
}

static uint32_t readdir_extn_files(hsm_hdl_t key_store_hdl,
				   char *dir_name,
				   char *exp_extn)
{
	uint32_t ret = 1;
	struct dirent *dir_data;
	DIR *dir_p;
	char *fpath;
	uint32_t fpath_len;

	if (!dir_name || !exp_extn)
		goto out;

	dir_p = opendir(dir_name);

	if (!dir_p) {
		printf("\nError: Failed to open %s directory. errno [%d]: %s\n",
		       dir_name,
		       errno,
		       strerror(errno));
		goto out;
	}

	// loop over directory's all files
	while ((dir_data = readdir(dir_p))) {
		if (extn_match(dir_data->d_name, exp_extn) == 0) {
			fpath_len = strlen(dir_name) + strlen(dir_data->d_name) + 1;
			fpath = (char *)malloc(fpath_len);

			snprintf(fpath,
				 fpath_len,
				 "%s%s",
				 dir_name,
				 dir_data->d_name);

			tv_tests(key_store_hdl, fpath);

			if (fpath)
				free(fpath);
		}
	}

	ret = 0;
out:
	if (dir_p)
		closedir(dir_p);

	return ret;
}

/* Run Test Vector tests */
void tv_tests_run(hsm_hdl_t key_store_hdl, uint8_t *tv_file_path)
{
	/*
	 * If Custom TV file path not provided, Loop over all .tv files in the
	 * Test Vectors DIR
	 */
	if (!tv_file_path) {
		readdir_extn_files(key_store_hdl, DEFAULT_TV_DIR, DEFAULT_TV_FEXTN);
		return;
	}

	tv_tests(key_store_hdl, tv_file_path);
}
