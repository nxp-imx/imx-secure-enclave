// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "common.h"
#include "she_api.h"
#include "plat_utils.h"

#define MAX_SHE_MU		(2u)
//!< Maximum SHE MUs supported.

she_hdl_t session_hdl;
open_svc_key_store_args_t key_store_args[MAX_KEY_STORE_SESSIONS];
op_open_utils_args_t utils_args[MAX_KEY_STORE_SESSIONS];
open_svc_cipher_args_t cipher_args[MAX_KEY_STORE_SESSIONS];

void she_test_sig_handler(int ht_signo, siginfo_t *ht_siginfo, void *ht_sigctx)
{
	if (session_hdl)
		she_close_session(session_hdl);

	exit(EXIT_SUCCESS);
}

void plat_she_test_usage(void)
{
	printf("she_test usage: seco_she_test [options]\n");
	printf("Options:\n");
	printf("1: <SHE session (0,1)>\n");
	printf("2: <no. of keystores (<=5)>\n");
	printf("3: <shared key store (<= no. of keystores)>\n");
}

void print_global_info(void)
{
	printf("-----------------------------------------------------------\n");
	printf("Global Info:\n");
	printf("-----------------------------------------------------------\n");

	printf("%s %s\n", get_soc_id_str(se_get_soc_id()),
	       get_soc_rev_str(se_get_soc_rev()));
	printf("%s Lifecycle\n", get_soc_lf_str(se_get_chip_lifecycle()));
	printf("Fips mode 0x%x\n", se_get_fips_mode());
	printf("LIB Version: %s\n", se_get_lib_version());
	printf("NVM Version: %s\n", se_get_nvm_version());
	printf("Build ID: %s\n", se_get_commit_id());
	printf("-----------------------------------------------------------\n");
}

void execute_tests(int session_id, int key_session_id)
{
	op_get_status_args_t op_get_status_args = {0};
	she_err_t err = SHE_NO_ERROR;
	int i, j;
	static int shared_id = (2 * (MAX_SHE_MU - 1) + (MAX_KEY_STORE_SESSIONS - 1)) *
			   ((MAX_SHE_MU - 1) + (MAX_KEY_STORE_SESSIONS - 1));

	i = key_session_id;
	j = session_id;

	/* Get the access to the SHE keystore */
	if (key_store_args[i].flags & KEY_STORE_OPEN_FLAGS_SHARED)
		key_store_args[i].key_store_identifier = shared_id++;
	else
		key_store_args[i].key_store_identifier = (2 * j + i) * (i + j);

	key_store_args[i].authentication_nonce =
		0xbec00001 + key_store_args[i].key_store_identifier;

	key_store_args[i].flags		 |= KEY_STORE_OPEN_FLAGS_CREATE |
					    KEY_STORE_OPEN_FLAGS_SHE |
					    KEY_STORE_OPEN_FLAGS_STRICT_OPERATION;

	key_store_args[i].min_mac_length        = 0x0;

#ifndef PSA_COMPLIANT
	key_store_args[i].max_updates_number   = 300;
#endif

	se_print("session id %d; key id : %d flags : 0x%x\n",
		 session_id,
		 key_store_args[i].key_store_identifier,
		 key_store_args[i].flags);

	err = do_she_create_storage_test(session_hdl,
					 &key_store_args[i]);
	if (err) {
		se_print("Err[0x%x]:storage Creation test Failed.\n", err);
		return;
	}

	se_print("Key Store handle : 0x%x\n", key_store_args[i].key_store_hdl);

	/* open SHE utils service. */
	err = she_open_utils(key_store_args[i].key_store_hdl,
			     &utils_args[i]);
	if (err) {
		se_err("Error: Failed to open SHE utils 0x%x\n", err);
		return;
	}

	se_print("Utils handle : 0x%x\n", utils_args[i].utils_handle);

	err = she_open_cipher_service(key_store_args[i].key_store_hdl,
				      &cipher_args[i]);
	if (err) {
		se_err("Failed to open cipher service 0x%x\n", err);
		return;
	}

	se_print("Cipher handle : 0x%x\n", cipher_args[i].cipher_hdl);

	err = she_get_status(utils_args[i].utils_handle,
			     &op_get_status_args);
	if (!err)
		se_print("CMD_GET_STATUS successful 0x%x\n", op_get_status_args.sreg);

	err = do_she_rng_test(session_hdl);
	if (err) {
		se_print("Error[0x%x]: RNG test Failed.\n", err);
		return;
	}

	err = she_get_status(utils_args[i].utils_handle,
			     &op_get_status_args);
	if (!err)
		se_print("CMD_GET_STATUS successful 0x%x\n", op_get_status_args.sreg);

	if (key_store_args[i].flags & KEY_STORE_OPEN_FLAGS_CREATE) {
		err = do_she_key_update_test(utils_args[i].utils_handle);
		if (err) {
			se_print("Error[0x%x]: Key Update test Failed.\n", err);
			return;
		}
	}

	err = do_she_fast_mac_test(utils_args[i].utils_handle);
	if (err) {
		se_print("Error[0x%x]: MAC test Failed.\n", err);
		return;
	}

	if (!she_v2x_mu) {
		err = do_she_ext_fast_mac_test
			(utils_args[i].utils_handle);
		if (err) {
			se_print("Error[0x%x]: EXT MAC test Failed.\n", err);
			return;
		}
	}

	err = do_she_get_id_test(utils_args[i].utils_handle);
	if (err)
		se_print("Error[0x%x]: GET ID test Failed.\n", err);

	err = do_she_plain_key_test(utils_args[i].utils_handle);
	if (err) {
		se_print("Error[0x%x]: Plain Key test Failed.\n", err);
		return;
	}

	err = do_she_cipher_test(cipher_args[i].cipher_hdl);
	if (err) {
		se_print("Error[0x%x]: Cipher test Failed.\n", err);
		return;
	}
}

void close_services(int key_session_id)
{
	int i;

	i = key_session_id;

	if (cipher_args[i].cipher_hdl)
		she_close_cipher_service(cipher_args[i].cipher_hdl);

	if (utils_args[i].utils_handle)
		she_close_utils(utils_args[i].utils_handle);

	if (key_store_args[i].key_store_hdl)
		she_close_key_store_service(key_store_args[i].key_store_hdl);
}

/* Test entry function. */
int main(int argc, char *argv[])
{
	uint8_t session_id;
	uint8_t num_of_keystores;
	uint8_t shared_keystore;
	open_session_args_t open_session_args;

	if (argc == 2 &&
			(strcmp("--help", argv[1]) == 0 || strcmp("-h", argv[1]) == 0)) {
		plat_she_test_usage();
		return 0;
	}

	if (argc < 4) {
		plat_she_test_usage();
		return 0;
	}

	session_id = atoi(argv[1]);
	num_of_keystores = atoi(argv[2]);
	shared_keystore = atoi(argv[3]);

	if (session_id > 1) {
		printf("supported SHE session id : 0, 1\n");
		return 0;
	}

	if (num_of_keystores > MAX_KEY_STORE_SESSIONS) {
		printf("supported num of keystores <= %d\n", MAX_KEY_STORE_SESSIONS);
		return 0;
	}

	if (shared_keystore > num_of_keystores) {
		printf("shared keystores must be <= num_of_keystores\n");
		return 0;
	}

	struct sigaction she_test_sigact = {0};
	she_err_t err;
	int i = 0;

	sigemptyset(&she_test_sigact.sa_mask);
	she_test_sigact.sa_flags = SA_SIGINFO;
	she_test_sigact.sa_sigaction = she_test_sig_handler;

	/* Register she test signal handler for SIGINT (CTRL+C) signal. */
	if (sigaction(SIGINT, &she_test_sigact, NULL)) {
		perror("failed to register she_test_sig_handler\n");
		return 0;
	}

	if (session_id)
		/* Open SHE1 session */
		open_session_args.mu_type = MU_CHANNEL_V2X_SV1;
	else
		open_session_args.mu_type = MU_CHANNEL_PLAT_SHE;

	err = she_open_session(&open_session_args, &session_hdl);
	if (err != SHE_NO_ERROR) {
		se_print("SHE%d open session failed err:0x%x\n", session_id, err);
		return 0;
	}
	se_print("SHE%d open session [0x%x] PASS\n",
		 session_id, session_hdl);

	print_global_info();

	if (se_get_soc_id() == SOC_IMX8DXL && shared_keystore) {
		se_print("Shared key store is not supported on this platform\n");
		return 0;
	}

	for (i = 0; i < (num_of_keystores - shared_keystore); i++)
		execute_tests(session_id, i);

	for (; i < num_of_keystores; i++) {
		key_store_args[i].flags = KEY_STORE_OPEN_FLAGS_SHARED;

		execute_tests(session_id, i);
	}

	/* close all opened services */
	for (i = 0; i < num_of_keystores; i++)
		close_services(i);

	/* close SHE session*/
	err = she_close_session(session_hdl);
	se_print("she_close_session ret:0x%x\n", err);

	return 0;
}
