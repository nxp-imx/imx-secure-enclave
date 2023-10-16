// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#ifndef COMMON_H
#define COMMON_H

#include "hsm_api.h"
#include "she_api.h"

#define DELETE	1
#define IMPORT	2
#define KEYATTR 3
#define PERM_TEST_KEY_ID  0x31110011u
#define PERM_TEST_KEY_GROUP  15

hsm_err_t do_mac_test(hsm_hdl_t key_store_hdl, hsm_hdl_t key_mgmt_hdl);
hsm_err_t do_cipher_test(hsm_hdl_t key_store_hdl, hsm_hdl_t key_mgmt_hdl);
hsm_err_t hsm_mac_test(hsm_hdl_t key_store_hdl, hsm_hdl_t key_mgmt_hdl);
hsm_err_t do_rng_test(hsm_hdl_t hsm_session_hdl);
hsm_err_t do_key_recovery_test(hsm_hdl_t key_store_hdl, hsm_hdl_t key_mgmt_hdl,
							uint32_t key_id,
							uint8_t *pub_key,
							uint32_t pub_key_sz);
void data_storage_test(hsm_hdl_t key_store_hdl, int arg);
#ifdef PSA_COMPLIANT
void enc_data_storage_test(hsm_hdl_t key_mgmt_hdl, hsm_hdl_t key_store_hdl);
#endif
void hash_test(hsm_hdl_t hash_sess);
hsm_err_t do_hash_test(hsm_hdl_t hash_session_hdl);
hsm_err_t do_hash_stream_test(hsm_hdl_t hash_session_hdl);

void hsm_sign_verify_tests(hsm_hdl_t sess_hdl, hsm_hdl_t key_store_hdl,
			   uint32_t key_id,
			   uint8_t *signature_data, uint32_t sign_data_sz,
			   uint8_t *hash_data, uint32_t hash_data_sz,
			   uint8_t *pub_key, uint32_t pub_key_sz);

hsm_err_t auth_enc_test(hsm_hdl_t key_store_hdl, hsm_hdl_t key_mgmt_hdl);
hsm_err_t gc_akey_gen_test(hsm_hdl_t session_hdl);
hsm_err_t gc_acrypto_test(hsm_hdl_t session_hdl);
hsm_err_t key_exchange_test(hsm_hdl_t hsm_session_hdl,
			    hsm_hdl_t key_store_hdl,
			    hsm_hdl_t key_mgmt_hdl);
hsm_err_t test_key_store_reprov_en(hsm_hdl_t session_hdl);

void get_device_info(hsm_hdl_t sess_hdl);
void perform_dev_attestation(hsm_hdl_t sess_hdl);
void lc_update_info(hsm_hdl_t sess_hdl);

void key_management(uint32_t key_op,
		    hsm_hdl_t key_mgmt_hdl,
		    uint32_t *key_id,
		    hsm_key_group_t key_group,
		    hsm_key_type_t key_type);
/**
 * This function prints the information of Global Info structure
 */
void print_global_info(void);
/* To run tests of test vector file */
void tv_tests_run(hsm_hdl_t key_store_hdl, uint8_t *tv_file_path);

/* To fetch the global session handle
 * opened as part of the test run
 */
hsm_hdl_t get_hsm_session_hdl(void);

void hexdump(uint32_t buf[], uint32_t size);
void hexdump_bb(uint8_t buf[], uint32_t size);
void word_byteswap(uint32_t *buf, uint32_t buf_len);

/* To send the commmand line
 * input to any test.
 */
int get_cmdline_arg(void);
time_t get_ele_perf_time(void);

she_err_t do_she_rng_test(she_hdl_t session_hdl);
she_err_t do_she_key_update_test(she_hdl_t utils_handle);
she_err_t do_she_plain_key_test(she_hdl_t utils_handle);
she_err_t do_she_cipher_test(she_hdl_t cipher_handle);
she_err_t do_she_fast_mac_test(she_hdl_t utils_handle);
she_err_t do_she_ext_fast_mac_test(she_hdl_t utils_handle);
she_err_t do_she_create_storage_test(she_hdl_t session_handle, she_hdl_t *key_store_hdl);
she_err_t do_she_get_id_test(she_hdl_t utils_handle);

#endif
