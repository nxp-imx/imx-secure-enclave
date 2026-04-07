// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2026 NXP
 */

#ifndef COMMON_H
#define COMMON_H

#include "hsm_api.h"
#include "she_api.h"
#include "test_utils.h"
#include "test_key_exchange.h"
#include "test_key_exchange_signed.h"

#define TEST_SUCCESS 0u
#define TEST_FAILED  1u

#define DELETE	1
#define IMPORT	2
#define KEYATTR 3
#define PERM_TEST_KEY_ID  0x31110011u
#define PERM_TEST_KEY_GROUP  15
//Test Status for Test Vectors
#define TEST_STATUS_INVALID -1
#define TEST_STATUS_FAILED  0
#define TEST_STATUS_SUCCESS 1
#define TEST_STATUS_SKIPPED 2
#define RSA_TCASE_ENABLED 1

#define TEST_INPUT_DIGEST  0
#define TEST_INPUT_MESSAGE 1

#define SUPPORT_KEY_EXCHANGE_PLAINTEXT_OUTPUT 0
#define SUPPORT_KEY_EXCHANGE_HKDF 0

hsm_err_t generate_test_key(hsm_hdl_t key_mgmt_hdl,
			    hsm_key_type_t key_type,
#ifdef PSA_COMPLIANT
			    hsm_bit_key_sz_t bit_key_sz,
			    hsm_key_lifetime_t key_lifetime,
			    hsm_key_usage_t key_usage,
			    hsm_permitted_algo_t permitted_algo,
			    hsm_key_lifecycle_t key_lifecycle,
#else
			    hsm_key_info_t key_info,
#endif
			    hsm_op_key_gen_flags_t flags,
			    hsm_key_group_t key_group,
#ifdef PSA_COMPLIANT
			    uint16_t priv_out_key_sz,
			    uint8_t *priv_out_key,
#endif
			    uint16_t out_size,
			    uint8_t *out_key,
			    uint32_t *key_id);

hsm_err_t test_generate_key(hsm_hdl_t key_mgmt_hdl);
hsm_err_t do_mac_test(hsm_hdl_t key_store_hdl, hsm_hdl_t key_mgmt_hdl);
hsm_err_t do_cipher_test(hsm_hdl_t key_store_hdl, hsm_hdl_t key_mgmt_hdl);
hsm_err_t hsm_mac_test(hsm_hdl_t key_store_hdl, hsm_hdl_t key_mgmt_hdl);
#ifdef PSA_COMPLIANT
hsm_err_t hsm_mac_plainkey_test(hsm_hdl_t key_store_hdl, hsm_hdl_t key_mgmt_hdl);
hsm_err_t hsm_mac_stream_test(hsm_hdl_t key_store_hdl, hsm_hdl_t key_mgmt_hdl,
			      hsm_permitted_algo_t key_permitted_algo,
			      hsm_key_type_t key_type,
			      hsm_bit_key_sz_t bit_key_sz,
			      char *algo_info);
#endif
hsm_err_t do_rng_test(hsm_hdl_t hsm_session_hdl);
hsm_err_t gen_rng_hex_str(hsm_hdl_t sess_hdl, op_get_random_args_t *rng_get_random_args,
			  uint8_t *rng_out_buff, bool flag_print_disabled);
hsm_err_t do_key_recovery_test(hsm_hdl_t key_store_hdl, hsm_hdl_t key_mgmt_hdl,
							uint32_t key_id,
							uint8_t *pub_key,
							uint32_t pub_key_sz);
void data_storage_test(hsm_hdl_t key_store_hdl, int arg);
#ifdef PSA_COMPLIANT
void enc_data_storage_test(hsm_hdl_t key_mgmt_hdl, hsm_hdl_t key_store_hdl);
void data_storage_delete_test(hsm_hdl_t key_store_hdl);
#endif
void hash_test(hsm_hdl_t hash_sess);
hsm_err_t do_hash_test(hsm_hdl_t hash_session_hdl);
hsm_err_t do_hash_stream_test(hsm_hdl_t hash_session_hdl);

hsm_err_t hsm_sign_verify_tests(hsm_hdl_t sess_hdl, hsm_hdl_t key_store_hdl,
				uint32_t key_id,
				hsm_signature_scheme_id_t scheme_id,
#ifdef PSA_COMPLIANT
				uint16_t key_type,
				hsm_pubkey_type_t pkey_type, hsm_bit_key_sz_t key_sz,
				uint8_t *sm2_id, uint16_t sm2_id_size,
#endif
				uint8_t *signature_data, uint32_t sign_data_sz,
				uint8_t *input_data, uint32_t input_data_sz,
#ifdef PSA_COMPLIANT
				uint8_t *priv_key, uint16_t priv_key_size,
#endif
				uint8_t *pub_key, uint32_t pub_key_sz,
				uint8_t input_data_type);

#ifdef PSA_COMPLIANT
hsm_err_t hsm_sign_verify_plaintext_tests(hsm_hdl_t sess_hdl,
					  hsm_hdl_t key_store_hdl,
					  hsm_hdl_t key_mgmt_hdl);
uint8_t hsm_sign_verify_sm2_tests(hsm_hdl_t sess_hdl, hsm_hdl_t key_store_hdl,
				  hsm_hdl_t key_mgmt_hdl);
#endif
void hsm_sign_verify_eddsa_tests(hsm_hdl_t sess_hdl,
				 hsm_hdl_t key_store_hdl,
				 hsm_hdl_t key_mgmt_hdl);

hsm_err_t auth_enc_test(hsm_hdl_t key_store_hdl, hsm_hdl_t key_mgmt_hdl);
hsm_err_t gc_akey_gen_test(hsm_hdl_t session_hdl);
hsm_err_t gc_acrypto_test(hsm_hdl_t session_hdl);
hsm_err_t gc_cipher_test(hsm_hdl_t hsm_session_hdl);
hsm_err_t gc_aead_test(hsm_hdl_t hsm_session_hdl);
hsm_err_t test_key_store_reprov_en(hsm_hdl_t session_hdl);
void set_signed_tests_en_status(uint8_t *oem_srkh, uint16_t len);
uint8_t get_signed_tests_en_status(void);
uint8_t get_signed_tests_key_type(void);

/**
 * This function is used to test the Public Key Attestation API
 */
void pub_key_attest_test(hsm_hdl_t key_store_hdl, hsm_hdl_t key_mgmt_hdl);

void get_device_info(hsm_hdl_t sess_hdl);
void dev_get_info(hsm_hdl_t sess_hdl);
void write_fuse(hsm_hdl_t sess_hdl);
void perform_dev_attestation(hsm_hdl_t sess_hdl);
void lc_update_info(hsm_hdl_t sess_hdl, hsm_lc_new_state_t state);

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
hsm_hdl_t get_key_store_hdl(void);
uint8_t get_rsa_tcase_status(void);

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
she_err_t do_she_ram_key_update_test(she_hdl_t utils_handle);
she_err_t do_she_plain_key_test(she_hdl_t utils_handle);
she_err_t do_she_cipher_test(she_hdl_t cipher_handle);
she_err_t do_she_fast_mac_test(she_hdl_t utils_handle);
she_err_t do_she_fast_mac_mubuff_v2_test(she_hdl_t utils_handle);
she_err_t do_she_ext_fast_mac_test(she_hdl_t utils_handle);
she_err_t do_she_mac_test(she_hdl_t mac_handle);
she_err_t do_she_create_storage_test(she_hdl_t session_handle,
				     open_svc_key_store_args_t *args);
she_err_t do_she_get_id_test(she_hdl_t utils_handle);
void she_tests(uint8_t SHE_id,
	       uint8_t mu_type,
	       uint8_t num_of_keystores,
	       uint8_t shared_keystore);

int shx_she_tests(int argc, char *argv[]);
void shx_tests_run(void);
int8_t get_supported_mu(uint8_t mu_type);
she_err_t open_session(open_session_args_t *args, struct she_session_hdl_s **hdl);

int shx_v2x_hsm_tests(int argc, char *argv[]);
#ifdef PSA_COMPLIANT
uint32_t test_ele_blob_unblob(hsm_hdl_t session_hdl, uint8_t *usr_ctx_buf,
			      uint32_t bsctx_val);
void test_mono_counter(hsm_hdl_t sess_hdl);
void test_asymmetric_crypto(hsm_hdl_t sess_hdl, hsm_hdl_t key_store_hdl);

#define GEN_ELE_KEY_BLOB_TYPE_DEK	"DEK"
#define GEN_ELE_KEY_BLOB_TYPE_OTFAD	"OTFAD"

#define GEN_ELE_KEY_BLOB_FORMAT_ALGO_AES_CBC "AES_CBC"
#define GEN_ELE_KEY_BLOB_FORMAT_ALGO_AES_CTR "AES_CBC"
#define GEN_ELE_KEY_BLOB_FORMAT_ALGO_SM4_CBC "SM4_CBC"
#define GEN_ELE_KEY_BLOB_FORMAT_ALGO_AES_XTS "AES_XTS"

#define GEN_ELE_KEY_BLOB_FORMAT_ALGO_KEY_SZ_AES128	"AES128"
#define GEN_ELE_KEY_BLOB_FORMAT_ALGO_KEY_SZ_AES192	"AES192"
#define GEN_ELE_KEY_BLOB_FORMAT_ALGO_KEY_SZ_AES256	"AES256"
#define GEN_ELE_KEY_BLOB_FORMAT_ALGO_KEY_SZ_SM4128	"SM4128"
#define GEN_ELE_KEY_BLOB_FORMAT_ALGO_SM4_EXCEPTION	"(only with OSSCA boot)"

#define GEN_ELE_KEY_BLOB_DEK_KEY_FILE_NAME \
	"Filename containing key-buffer, in binary-format"
#define GEN_ELE_KEY_BLOB_OUTPUT_DEK_BLOB_FILENAME \
	"Filename to save generated ELE DEK-blob, in binary-format"
uint16_t gen_ele_key_blob_get_keysize(hsm_op_gen_ele_key_blob_flags_t flag, char *str);
hsm_op_gen_ele_key_blob_algo_t
	gen_ele_key_blob_get_algo(hsm_op_gen_ele_key_blob_flags_t flag, char *str);

hsm_err_t test_gen_ele_key_blob(hsm_hdl_t sess_hdl,
				hsm_op_gen_ele_key_blob_flags_t flag, uint32_t key_id,
				hsm_op_gen_ele_key_blob_algo_t algo, uint8_t *payload,
				uint8_t payload_len, uint8_t *ele_key_blob,
				uint8_t *ele_key_blob_sz);
#endif
#define GEN_RNG_OUT_FILENAME \
	"to save generated RNG number, in binary format"
#define GEN_RNG_OUT_SILENT \
	"to suppress writing to console or to file"


#endif
