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
#include <unistd.h>

#include "test_common.h"
#include "test_common_tv.h"
#include "plat_utils.h"

#define TV_TEMP_KEY_STORE_ID 0xABCC
#define TV_TEMP_KEY_STORE_NONCE 0x1233
#define SLEEP_INTERVAL 3

/**
 * Stop the existing/older nvm_daemon and start the new
 * nvm_dameon on new location for test vectors only.
 */
void new_nvm_daemon(void)
{
	const char *conf_setup = "nvmd_conf_setup.sh custom ";
	const char *dir_name = "dir_name=/etc/ele_temp/ ";
	const char *filename = "filename=/etc/ele_temp/ele_nvm_master ";
	const char *flag = "flag=0x80 ";
	const char *type = "type=ELE";

	size_t total_length = strlen(conf_setup) + strlen(dir_name)
			      + strlen(filename) + strlen(flag)
			      + strlen(type) + 1u;
	char *command = (char *)malloc(total_length * sizeof(char));

	if (!command) {
		se_err("\nError: Couldn't allocate memory for Command\n");
		goto out;
	}

	snprintf(command, total_length, "%s%s%s%s%s",
		 conf_setup, dir_name, filename, flag, type);

	if (system("systemctl stop nvm_daemon"))
		printf("Error: Failed to stop NVM Daemon\n");

	if (system("rm -rf /var/lib/se/persistent/*"))
		printf("Error: Failed to remove persistent files\n");

	if (system(command))
		printf("Error: Failed to execute nvmd_conf_setup.sh\n");

	if (system("systemctl start nvm_daemon"))
		printf("Error: Failed to start NVM Daemon\n");

	sleep(SLEEP_INTERVAL);
out:
	if (command)
		free(command);
}

/**
 * Stop the new nvm_daemon and remove the files, directories
 * created at respective location to reuse the location again.
 * Restart the existing/older test nvm_daemon at the end again.
 */
void end_nvm_daemon(void)
{
	const char *conf_setup = "nvmd_conf_setup.sh custom ";
	const char *dir_name = "dir_name=/etc/ele/ ";
	const char *filename = "filename=/etc/ele/ele_nvm_master ";
	const char *flag = "flag=0x80 ";
	const char *type = "type=ELE";

	size_t total_length = strlen(conf_setup) + strlen(dir_name)
			      + strlen(filename) + strlen(flag)
			      + strlen(type) + 1u;
	char *command = (char *)malloc(total_length * sizeof(char));

	if (!command) {
		se_err("\nError: Couldn't allocate memory for Command\n");
		goto out;
	}

	snprintf(command, total_length, "%s%s%s%s%s",
		 conf_setup, dir_name, filename, flag, type);

	if (system("systemctl stop nvm_daemon"))
		printf("Error: Failed to execute nvmd_conf_setup.sh\n");

	if (system("rm -rf /etc/ele_temp*"))
		printf("Error: Failed to remove new directories\n");

	if (system("rm -rf /var/lib/se/persistent/*"))
		printf("Error: Failed to remove persistent files\n");

	if (system(command))
		printf("Error: Failed to execute nvmd_conf_setup.sh\n");

	if (system("systemctl start nvm_daemon"))
		printf("Error: Failed to start NVM Daemon\n");

	sleep(SLEEP_INTERVAL);
out:
	if (command)
		free(command);
}

/**
 * After stopping the existing/older key store, open new Key Store for
 * test vectors only.
 */
hsm_hdl_t open_new_key_store(hsm_hdl_t hsm_session_hdl)
{
	hsm_err_t err;
	open_svc_key_store_args_t key_store_args = {0};
	hsm_hdl_t key_store_hdl;

	key_store_args.key_store_identifier = TV_TEMP_KEY_STORE_ID;
	key_store_args.authentication_nonce = TV_TEMP_KEY_STORE_NONCE;
#ifndef PSA_COMPLIANT
	key_store_args.max_updates_number   = 100;
#endif
	key_store_args.flags                = HSM_SVC_KEY_STORE_FLAGS_CREATE;
	err = hsm_open_key_store_service(hsm_session_hdl, &key_store_args,
					 &key_store_hdl);
	se_info("hsm_open_key_store_service (create) ret:0x%x\n", err);

	return key_store_hdl;
}

/**
 *  Load existing/older Key Store
 */
hsm_hdl_t open_old_key_store(hsm_hdl_t hsm_session_hdl, hsm_hdl_t key_store_hdl)
{
	hsm_err_t err;
	open_svc_key_store_args_t key_store_args = {0};

	key_store_args.key_store_identifier = 0xABCD;
	key_store_args.authentication_nonce = 0x1234;
#ifndef PSA_COMPLIANT
	key_store_args.max_updates_number   = 100;
#endif
	key_store_args.flags                = HSM_SVC_KEY_STORE_FLAGS_CREATE;
	err = hsm_open_key_store_service(hsm_session_hdl, &key_store_args,
					 &key_store_hdl);
	se_info("hsm_open_key_store_service (create) ret:0x%x\n", err);

	if (err == HSM_KEY_STORE_CONFLICT) {
		key_store_args.flags            = HSM_SVC_KEY_STORE_FLAGS_LOAD;
		err = hsm_open_key_store_service(hsm_session_hdl, &key_store_args,
						 &key_store_hdl);
		se_info("\nhsm_open_key_store_service (load) ret:0x%x\n", err);
	}

	return key_store_hdl;
}

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
	uint16_t trng_passed = 0;
	uint16_t trng_failed = 0;
	uint16_t trng_invalid = 0;
	uint16_t trng_total = 0;
	uint16_t tauth_enc_passed = 0;
	uint16_t tauth_enc_failed = 0;
	uint16_t tauth_enc_invalid = 0;
	uint16_t tauth_enc_total = 0;
	uint16_t tgc_acrypto_passed = 0;
	uint16_t tgc_acrypto_failed = 0;
	uint16_t tgc_acrypto_invalid = 0;
	uint16_t tgc_acrypto_total = 0;
	uint16_t tenc_data_storage_passed = 0;
	uint16_t tenc_data_storage_failed = 0;
	uint16_t tenc_data_storage_invalid = 0;
	uint16_t tenc_data_storage_total = 0;

	char *line = NULL;
	char *check_invalid = NULL;
	size_t len = 0;
	FILE *fp = NULL;
	ssize_t read;

	hsm_err_t err;
	hsm_hdl_t hsm_session_hdl = get_hsm_session_hdl();

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

				/* Close existing/old Key Store */
				if (memcmp(line, "OLD_KEY_STORE_CLOSE", 19) == 0) {
					err = hsm_close_key_store_service(key_store_hdl);
					se_info("hsm_close_key_store_service");
					se_info("ret:0x%x\n", err);
				}

				/* Open new nvm_daemon */
				if (memcmp(line, "NVM_START", 9) == 0)
					new_nvm_daemon();

				/* Open New Key Store Service*/
				if (memcmp(line, "OPEN_KEY_STORE_SRV", 18) == 0)
					key_store_hdl = open_new_key_store
							(hsm_session_hdl);

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
				/* RNG Test */
				if (memcmp(line, "TEST_RNG", 8) == 0)
					rng_test_tv(fp, line,
						    &trng_passed, &trng_failed,
						    &trng_invalid,
						    &trng_total);

				/* Authenticated Encryption Tests */
				if (memcmp(line, "TEST_AUTH_ENC", 13) == 0)
					auth_enc_test_tv(key_store_hdl, fp, line,
							 &tauth_enc_passed,
							 &tauth_enc_failed,
							 &tauth_enc_invalid,
							 &tauth_enc_total);

#ifdef PSA_COMPLIANT
				/* GC ACRYPTO Test*/
				if (se_get_soc_id() != SOC_IMX8ULP &&
				    memcmp(line, "TEST_GC_ACRYPTO", 15) == 0)
					gc_acrypto_test_tv(key_store_hdl, fp,
							   line, &tgc_acrypto_passed,
							   &tgc_acrypto_failed,
							   &tgc_acrypto_invalid,
							   &tgc_acrypto_total);
#endif
				/* ENC DATA STORAGE Test*/
				if (memcmp(line, "TEST_ENC_DATA_STORAGE", 21) == 0)
					enc_data_storage_test_tv
						(key_store_hdl, fp, line,
						 &tenc_data_storage_passed,
						 &tenc_data_storage_failed,
						 &tenc_data_storage_invalid,
						 &tenc_data_storage_total);
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
				/* Close New Key Store */
				if (memcmp(line, "CLOSE_KEY_STORE_SRV", 19) == 0) {
					err = hsm_close_key_store_service(key_store_hdl);
					se_info("hsm_close_key_store_service");
					se_info("ret:0x%x\n", err);
				}

				/* Stop new_daemon */
				if (memcmp(line, "NVM_END", 7) == 0)
					end_nvm_daemon();

				/* Load the existing/old key store */
				if (memcmp(line, "OPEN_OLD_KEY_STORE", 18) == 0)
					key_store_hdl = open_old_key_store
							(hsm_session_hdl,
							 key_store_hdl);
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
		printf("TESTS REPORT DATA STORAGE:: ");
		printf("TOTAL: %u, SUCCESS: %u, FAILED: %u, INVALID: %u",
		       tdata_total, tdata_passed, tdata_failed, tdata_invalid);
		printf("\n-----------------------------------------------------------------\n\n");
	}

	if (trng_total > 0) {
		printf("TESTS REPORT RNG:: ");
		printf("TOTAL: %u, SUCCESS: %u, FAILED: %u, INVALID: %u",
		       trng_total, trng_passed, trng_failed, trng_invalid);
		printf("\n---------------------------------------------------------\n\n");
	}

	if (tauth_enc_total > 0) {
		printf("TESTS REPORT AUTHENTICATED ENCRYPTION:: ");
		printf("TOTAL: %u, SUCCESS: %u, FAILED: %u, INVALID: %u",
		       tauth_enc_total, tauth_enc_passed, tauth_enc_failed,
		       tauth_enc_invalid);
		printf("\n---------------------------------------------------------\n\n");
	}

	if (tgc_acrypto_total > 0) {
		printf("TESTS REPORT GC ACRYPTO:: ");
		printf("TOTAL: %u, SUCCESS: %u, FAILED: %u, INVALID: %u",
		       tgc_acrypto_total, tgc_acrypto_passed, tgc_acrypto_failed,
		       tgc_acrypto_invalid);
		printf("\n-------------------------------------------------------\n\n");
	}

	if (tenc_data_storage_total > 0) {
		printf("TESTS REPORT ENC DATA STORAGE: ");
		printf(" TOTAL: %u, SUCCESS: %u, FAILED: %u, INVALID: %u",
		       tenc_data_storage_total, tenc_data_storage_passed,
		       tenc_data_storage_failed, tenc_data_storage_invalid);
		printf("\n-------------------------------------------------------\n\n");
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
