// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2025 NXP
 */

#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "test_common.h"
#include "she_api.h"
#include "plat_utils.h"

#define MAX_SHE_MU		(2u)
//!< Maximum SHE MUs supported.

#define SHE_TEST_SESSIONS	2

static she_hdl_t session_hdl;
static int shared_id;

open_session_args_t session_args[SHE_TEST_SESSIONS] = {0};
open_svc_key_store_args_t key_store_args[SHE_TEST_SESSIONS][MAX_KEY_STORE_SESSIONS];
op_open_utils_args_t utils_args[SHE_TEST_SESSIONS][MAX_KEY_STORE_SESSIONS];
open_svc_cipher_args_t cipher_args[SHE_TEST_SESSIONS][MAX_KEY_STORE_SESSIONS];
open_svc_mac_args_t mac_args[SHE_TEST_SESSIONS][MAX_KEY_STORE_SESSIONS];

void she_test_sig_handler(int ht_signo, siginfo_t *ht_siginfo, void *ht_sigctx)
{
	int i;

	for (i = 0; i < SHE_TEST_SESSIONS; i++)
		/* close SHE session*/
		if (session_args[i].session_hdl)
			she_close_session(session_args[i].session_hdl);

	exit(EXIT_SUCCESS);
}

void print_global_info(void)
{
	printf("-----------------------------------------------------------\n");
	printf("Global Info:\n");
	printf("-----------------------------------------------------------\n");

	if (se_get_soc_id() == SOC_IMX8DXL)
		printf("%s %s %s\n", get_soc_id_str(se_get_soc_id()),
		       get_soc_rev_str(se_get_soc_rev()),
		       get_board_type_str(se_get_board_type()));
	else
		printf("%s %s\n", get_soc_id_str(se_get_soc_id()),
		       get_soc_rev_str(se_get_soc_rev()));

	printf("%s Lifecycle\n", get_soc_lf_str(se_get_chip_lifecycle()));
	printf("Fips mode 0x%x\n", se_get_fips_mode());
	printf("LIB Version: %s\n", se_get_lib_version());
	printf("NVM Version: %s\n", se_get_nvm_version());
	printf("Build ID: %s\n", se_get_commit_id());
	printf("-----------------------------------------------------------\n");
}

void execute_tests(int session_id, int SHE_id, int key_store_num)
{
	op_get_status_args_t op_get_status_args = {0};
	she_err_t err = SHE_NO_ERROR;
	int i, j, k;

	i = key_store_num;
	j = session_id;
	k = SHE_id;

	/* Get the access to the SHE keystore */
	if (key_store_args[j][i].flags & KEY_STORE_OPEN_FLAGS_SHARED)
		key_store_args[j][i].key_store_identifier = shared_id++;
	else
		key_store_args[j][i].key_store_identifier = (2 * k + i) * (i + k);

	key_store_args[j][i].authentication_nonce =
		0xbec00001 + key_store_args[j][i].key_store_identifier;

	key_store_args[j][i].flags		 |= KEY_STORE_OPEN_FLAGS_CREATE |
					    KEY_STORE_OPEN_FLAGS_SHE |
					    KEY_STORE_OPEN_FLAGS_STRICT_OPERATION |
					    KEY_STORE_OPEN_FLAGS_SET_MAC_LEN;

	key_store_args[j][i].min_mac_length        = 32;

#ifndef PSA_COMPLIANT
	key_store_args[j][i].max_updates_number   = 300;
#endif

	se_print("SHE%d[%d]; key id : %d flags : 0x%x\n",
		 SHE_id, j,
		 key_store_args[j][i].key_store_identifier,
		 key_store_args[j][i].flags);

	err = do_she_create_storage_test(session_hdl,
					 &key_store_args[j][i]);
	if (err) {
		se_print("Err[0x%x]:storage Creation test Failed.\n", err);
		return;
	}

	se_print("Key Store handle : 0x%x\n", key_store_args[j][i].key_store_hdl);

	/* open SHE utils service. */
	err = she_open_utils(key_store_args[j][i].key_store_hdl,
			     &utils_args[j][i]);
	if (err) {
		se_err("Error: Failed to open SHE utils 0x%x\n", err);
		return;
	}

	se_print("Utils handle : 0x%x\n", utils_args[j][i].utils_handle);

	err = she_open_cipher_service(key_store_args[j][i].key_store_hdl,
				      &cipher_args[j][i]);
	if (err) {
		se_err("Failed to open cipher service 0x%x\n", err);
		return;
	}

	se_print("Cipher handle : 0x%x\n", cipher_args[j][i].cipher_hdl);

	err = she_open_mac_service(key_store_args[j][i].key_store_hdl, &mac_args[j][i]);
	if (err) {
		if (err != SHE_FEATURE_NOT_SUPPORTED) {
			se_err("Failed to open mac service 0x%x\n", err);
			return;
		}
	} else {
		se_print("mac handle : 0x%x\n", mac_args[j][i].mac_serv_hdl);
	}

	err = she_get_status(utils_args[j][i].utils_handle,
			     &op_get_status_args);
	if (!err)
		se_print("CMD_GET_STATUS successful 0x%x\n", op_get_status_args.sreg);

	err = do_she_rng_test(session_hdl);
	if (err) {
		se_print("Error[0x%x]: RNG test Failed.\n", err);
		return;
	}

	err = she_get_status(utils_args[j][i].utils_handle,
			     &op_get_status_args);
	if (!err)
		se_print("CMD_GET_STATUS successful 0x%x\n", op_get_status_args.sreg);

	if (key_store_args[j][i].flags & KEY_STORE_OPEN_FLAGS_CREATE) {
		err = do_she_key_update_test(utils_args[j][i].utils_handle);
		if (err) {
			se_print("Error[0x%x]: Key Update test Failed.\n", err);
			return;
		}
	}

	err = do_she_ram_key_update_test(utils_args[j][i].utils_handle);
	if (err) {
		se_print("Error[0x%x]: RAM Key Update test Failed.\n", err);
		return;
	}

	err = do_she_fast_mac_test(utils_args[j][i].utils_handle);
	if (err) {
		se_print("Error[0x%x]: FAST MAC test Failed.\n", err);
		return;
	}

	err = do_she_fast_mac_mubuff_v2_test(utils_args[j][i].utils_handle);
	if (err && err != SHE_FEATURE_NOT_SUPPORTED) {
		se_print("Error[0x%x]: FAST MAC V2 test Failed.\n", err);
		return;
	}

	err = do_she_ext_fast_mac_test(utils_args[j][i].utils_handle);
	if (err && err != SHE_FEATURE_NOT_SUPPORTED) {
		se_print("Error[0x%x]: EXT FAST MAC test Failed.\n", err);
		return;
	}

	err = do_she_get_id_test(utils_args[j][i].utils_handle);
	if (err)
		se_print("Error[0x%x]: GET ID test Failed.\n", err);

	err = do_she_plain_key_test(utils_args[j][i].utils_handle);
	if (err) {
		se_print("Error[0x%x]: Plain Key test Failed.\n", err);
		return;
	}

	err = do_she_mac_test(mac_args[j][i].mac_serv_hdl);
	if (err) {
		if (err != SHE_FEATURE_NOT_SUPPORTED) {
			se_print("Error[0x%x]: MAC test Failed.\n", err);
			return;
		}
	}

	err = do_she_cipher_test(cipher_args[j][i].cipher_hdl);
	if (err) {
		se_print("Error[0x%x]: Cipher test Failed.\n", err);
		return;
	}
}

void close_services(int session_id, int key_store_num)
{
	int i, j;

	i = key_store_num;
	j = session_id;

	if (cipher_args[j][i].cipher_hdl)
		she_close_cipher_service(cipher_args[j][i].cipher_hdl);

	if (mac_args[j][i].mac_serv_hdl)
		she_close_mac_service(mac_args[j][i].mac_serv_hdl);

	if (utils_args[j][i].utils_handle)
		she_close_utils(utils_args[j][i].utils_handle);

	if (key_store_args[j][i].key_store_hdl)
		she_close_key_store_service(key_store_args[j][i].key_store_hdl);
}

/*
 * This functional:
 * 1.	opens a session on HSM MU (Received as input args)
 * 2.	Populate global info and on basis of soc id and board type,
 * 3.	Return the support MU TYPE for SHE depending on the SoC ID and Board Type.
 */
int8_t get_supported_mu(uint8_t mu_type)
{
	struct she_session_hdl_s *hdl = NULL;
	uint32_t err;
	uint8_t board_type = 0;

	open_session_args_t open_session_args = {0};

	/* Open HSM session on V2X */
	open_session_args.mu_type = mu_type;
	err = open_session(&open_session_args, &hdl);
	if (err) {
		printf("open_session failed for HSM, err:0x%x\n", err);
		return -1;
	}

	populate_global_info(open_session_args.session_hdl);
	she_close_session(open_session_args.session_hdl);

	/* return V2X_SHE for i.MX95, as only V2X is supported on i.MX95 */
	if (se_get_soc_id() != SOC_IMX8DXL &&
	    se_get_soc_id() != SOC_IMX8QXP)
		return V2X_SHE;

	if (se_get_board_type() == IMX8DXL_DL1)
		return SHE1;
	if (se_get_board_type() == IMX8DXL_DL3)
		return V2X_SHE;
	if (se_get_board_type() == IMX8DXL_DL2)
		return 0;

	return SHE1;
}

/* Test entry function. */
void she_tests(uint8_t SHE_id,
	       uint8_t mu_type,
	       uint8_t num_of_keystores,
	       uint8_t shared_keystore)
{
	uint8_t session_id = 0;
	uint8_t she_sess_count = 1;

	if (SHE_id > 1) {
		printf("supported SHE id : 0, 1\n");
		return;
	}

	if (num_of_keystores > MAX_KEY_STORE_SESSIONS) {
		printf("supported num of keystores <= %d\n", MAX_KEY_STORE_SESSIONS);
		return;
	}

	if (shared_keystore > num_of_keystores) {
		printf("shared keystores must be <= num_of_keystores\n");
		return;
	}

	struct sigaction she_test_sigact = {0};
	she_err_t err;
	int i = 0, j = 0;

	sigemptyset(&she_test_sigact.sa_mask);
	she_test_sigact.sa_flags = SA_SIGINFO;
	she_test_sigact.sa_sigaction = she_test_sig_handler;

	/* Register she test signal handler for SIGINT (CTRL+C) signal. */
	if (sigaction(SIGINT, &she_test_sigact, NULL)) {
		perror("failed to register she_test_sig_handler\n");
		return;
	}

	if (se_get_soc_id() == SOC_IMX95 ||
	    se_get_soc_id() == SOC_IMX943)
		she_sess_count = SHE_TEST_SESSIONS;

	for (j = 0; j < she_sess_count; j++) {
		session_args[j].mu_type = mu_type;

		err = she_open_session(&session_args[j], &session_hdl);
		if (err != SHE_NO_ERROR) {
			se_print("SHE%d[%d] open session failed err:0x%x\n",
				 SHE_id, j, err);
			break;
		}
		se_print("SHE%d[%d] open session [0x%x] PASS\n",
			 SHE_id, j, session_hdl);

		if (!j) //print information only once
			print_global_info();

		if (se_get_soc_id() == SOC_IMX8DXL && shared_keystore) {
			se_print("Shared key store is not supported on this platform\n");
			break;
		}

		if (!j) {// open non-shared key store for session 0 only
			for (i = 0; i < (num_of_keystores - shared_keystore); i++)
				execute_tests(j, SHE_id, i);
		} else {
			i = num_of_keystores - shared_keystore;
		}

		shared_id = (2 * (MAX_SHE_MU - 1) + (MAX_KEY_STORE_SESSIONS - 1)) *
			    ((MAX_SHE_MU - 1) + (MAX_KEY_STORE_SESSIONS - 1));
		for (; i < num_of_keystores; i++) {
			key_store_args[j][i].flags = KEY_STORE_OPEN_FLAGS_SHARED;
			execute_tests(j, SHE_id, i);
		}
	}

	for (j = 0; j < she_sess_count; j++) {
		/* close all opened services */
		for (i = 0; i < num_of_keystores; i++)
			close_services(j, i);
	}

	for (j = 0; j < she_sess_count; j++) {
		/* close SHE session*/
		if (session_args[j].session_hdl) {
			err = she_close_session(session_args[j].session_hdl);
			se_print("she_close_session[%d] ret:0x%x\n", j, err);
		}
	}
}
