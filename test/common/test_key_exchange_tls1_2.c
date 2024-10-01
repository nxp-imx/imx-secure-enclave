// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#include <stdio.h>

#ifdef PSA_COMPLIANT
#include <mbedtls/ssl.h>

#include "mbedtls_utils.h"

#include "test_common.h"
#include "hsm_api.h"

static uint32_t get_key_id_from_buffer(uint8_t *key_ids_buffer,
				       uint8_t key_ids_buffer_len)
{
	uint32_t key_id = 0;

	if (!key_ids_buffer || key_ids_buffer_len < sizeof(uint32_t))
		return key_id;
	/**
	 * Preparing Key ID of 4 bytes size, byte-by-byte from the provided
	 * Key IDs buffer
	 */
	for (uint8_t i = 0; i < sizeof(uint32_t); i++)
		key_id = (key_id << 8) | key_ids_buffer[i];

	return key_id;
}

static hsm_err_t test_tls1_2_kb_keys_hmac(hsm_hdl_t key_store_hdl,
					  uint32_t key_id,
					  hsm_permitted_algo_t algo)
{
	hsm_err_t err = HSM_GENERAL_ERROR;
	op_mac_one_go_args_t mac_args;
	uint8_t mac[48] = {0};
	uint8_t mac_size;

	// MAC size determined by SHAXXX output length in bytes
	if (algo == PERMITTED_ALGO_HMAC_SHA256)
		mac_size = 32;
	else if (algo == PERMITTED_ALGO_HMAC_SHA384)
		mac_size = 48;
	else
		goto out;

	memset(&mac_args, 0, sizeof(op_mac_one_go_args_t));

	mac_args.key_identifier = key_id;
	mac_args.algorithm = algo;
	mac_args.flags = HSM_OP_MAC_ONE_GO_FLAGS_MAC_GENERATION;
	mac_args.payload = test_msg;
	mac_args.payload_size = sizeof(test_msg);
	mac_args.mac = mac;
	mac_args.mac_size = mac_size;

	err = hsm_do_mac(key_store_hdl, &mac_args);
	if (err != HSM_NO_ERROR)
		printf("\nhsm_do_mac (generate) err: 0x%x\n", err);

	mac_args.flags = HSM_OP_MAC_ONE_GO_FLAGS_MAC_VERIFICATION;
	mac_args.mac_size = mac_size;

	err = hsm_do_mac(key_store_hdl, &mac_args);
	if (err != HSM_NO_ERROR)
		printf("\nhsm_do_mac (verify) err: 0x%x\n", err);
out:
	return err;
}

static hsm_err_t test_tls1_2_kb_keys_cbc(hsm_hdl_t key_store_hdl,
					 uint32_t key_id)
{
	hsm_err_t err;
	op_cipher_one_go_args_t cipher_args;
	uint8_t ciphertext[32] = {0};
	uint8_t deciphered_data[32] = {0};

	memset(&cipher_args, 0, sizeof(op_cipher_one_go_args_t));

	cipher_args.key_identifier = key_id;
	cipher_args.iv = iv;
	cipher_args.iv_size = sizeof(iv);
	cipher_args.cipher_algo = HSM_CIPHER_ONE_GO_ALGO_CBC;
	cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_ENCRYPT;
	cipher_args.input = test_msg;
	cipher_args.output = ciphertext;
	cipher_args.input_size = sizeof(test_msg);
	cipher_args.output_size = sizeof(ciphertext);

	err = hsm_do_cipher(key_store_hdl, &cipher_args);
	if (err != HSM_NO_ERROR)
		printf("hsm_cipher_one_go (encrypt) err: 0x%x\n", err);

	cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_DECRYPT;
	cipher_args.input = ciphertext;
	cipher_args.output = deciphered_data;
	cipher_args.input_size = sizeof(ciphertext);
	cipher_args.output_size = sizeof(deciphered_data);

	err = hsm_do_cipher(key_store_hdl, &cipher_args);
	if (err != HSM_NO_ERROR)
		printf("hsm_cipher_one_go (decrypt) err: 0x%x\n", err);

	if (memcmp(test_msg, deciphered_data, sizeof(test_msg)))
		printf("\nDecrypted data doesn't match encrypted data [FAIL]\n");

out:
	return err;
}

/**
 *       TLS 1.2 RFC 5246 : Section 8.1
 *
 *       master_secret = PRF(pre_master_secret, "master secret",
 *                           ClientHello.random + ServerHello.random)
 *                           [0..47];
 */
static void test_tls1_2_master_secret(hsm_hdl_t key_mgmt_hdl,
				      uint32_t *master_secret_key_id,
				      uint8_t *master_secret,
				      uint32_t master_secret_len)
{
	hsm_err_t err;
	in_content_tls1_2_master_secret_args_t in_content;
	op_key_exchange_args_t key_ex_args;
	op_generate_key_args_t key_gen_args;
	uint8_t fw_pub_key[64] = {0}; // 2 * BITS_TO_BYTES(HSM_KEY_SIZE_ECC_NIST_256)
	uint32_t fw_key_id = 0;
	uint8_t mbedtls_master_secret[BITS_TO_BYTES(HSM_KEY_SIZE_DERIVE_384)] = {0};
	static char mbedtls_premaster_secret[48] = {0};
	uint32_t mbedtls_premaster_secret_len = sizeof(mbedtls_premaster_secret);
	uint32_t tls1_2_label_ms_len = strlen(test_tls1_2_label_master_secret);
	uint32_t ret;

	printf("\nTLS 1.2 Master Secret:\n");
	printf("--------------------------\n");

	/* 1. Generate ELE Private Key for Premaster secret generation */
	memset(&key_gen_args, 0, sizeof(op_generate_key_args_t));

	key_gen_args.key_identifier = &fw_key_id;
	key_gen_args.key_group = 40;
	key_gen_args.key_lifetime = HSM_SE_KEY_STORAGE_VOLATILE;
	key_gen_args.key_usage = HSM_KEY_USAGE_DERIVE;
	key_gen_args.permitted_algo = PERMITTED_ALGO_TLS1_2_MASTER_SECRET_SHA256;
	key_gen_args.flags = 0x0;
	key_gen_args.key_type = HSM_KEY_TYPE_ECC_NIST;
	key_gen_args.bit_key_sz = HSM_KEY_SIZE_ECC_NIST_256;
	key_gen_args.key_lifecycle = 0x0; // Current Device Lifecycle
	key_gen_args.out_key = fw_pub_key;
	key_gen_args.out_size = sizeof(fw_pub_key);

	err = hsm_generate_key(key_mgmt_hdl, &key_gen_args);
	if (err != HSM_NO_ERROR) {
		printf("\nhsm_generate_key err: 0x%x\n", err);
		return;
	}

	/* 2. Prepare Input Content for TLS 1.2 master secret */
	memset(&in_content, 0, sizeof(in_content_tls1_2_master_secret_args_t));

	in_content.ver = 0x1;
	in_content.rsv = 0x0;
	in_content.keystore_id = TEST_KEYSTORE_ID;
	in_content.tls1_2_algo = HSM_KEY_DERIVATION_TLS1_2_MASTER_SECRET_SHA256;
	in_content.priv_key_id = fw_key_id;
	in_content.derived_key_type = HSM_KEY_TYPE_DERIVE; //Ignored
	in_content.derived_key_bits_size = HSM_KEY_SIZE_DERIVE_384; //Ignored
	in_content.derived_key_lifetime = HSM_SE_KEY_STORAGE_VOLATILE; //Ignored
	in_content.derived_key_usage = HSM_KEY_USAGE_DERIVE; //Ignored
	in_content.derived_key_permitted_algo = 0x0; // Ignored by ELE
	in_content.derived_key_lifecycle = 0x0; // Ignored by ELE. Set to Current
	in_content.derived_key_id = 0x0; // Ignored by ELE
	in_content.reserved = 0x0;

	/* 3.1. Derived TLS 1.2 Master Secret Key stored in ELE FW. */
	memset(&key_ex_args, 0, sizeof(op_key_exchange_args_t));

	key_ex_args.flags = HSM_OP_KEY_EXCHANGE_FLAGS_INPUT_PLAINTEXT_CONTENT;
	key_ex_args.in_content_sz = sizeof(in_content);
	key_ex_args.in_content = (uint8_t *)(&in_content);
	key_ex_args.in_pub_buffer_sz = sizeof(ecc_256_pub_key);
	key_ex_args.in_pub_buffer = ecc_256_pub_key;
	key_ex_args.user_fixed_info_sz = sizeof(test_tls1_2_ms_seed);
	key_ex_args.user_fixed_info = (uint8_t *)test_tls1_2_ms_seed;
	key_ex_args.output_sz = 0;
	key_ex_args.output = NULL;

	err = hsm_key_exchange(key_mgmt_hdl, &key_ex_args);
	printf("\nhsm_key_exchange [TLS 1.2 Master Secret case #1.1] err: 0x%x\n", err);
	printf("\t--Derived Key ID: 0x%x\n", key_ex_args.out_derived_key_id);

	*master_secret_key_id = key_ex_args.out_derived_key_id;

	/* 3.2. Export/Output Derived TLS 1.2 Master Secret Key */
	memset(&key_ex_args, 0, sizeof(op_key_exchange_args_t));

	key_ex_args.flags = HSM_OP_KEY_EXCHANGE_FLAGS_INPUT_PLAINTEXT_CONTENT |
		HSM_OP_KEY_EXCHANGE_FLAGS_RETURN_OUTPUT;
	key_ex_args.in_content_sz = sizeof(in_content);
	key_ex_args.in_content = (uint8_t *)(&in_content);
	key_ex_args.in_pub_buffer_sz = sizeof(ecc_256_pub_key);
	key_ex_args.in_pub_buffer = ecc_256_pub_key;
	key_ex_args.user_fixed_info_sz = sizeof(test_tls1_2_ms_seed);
	key_ex_args.user_fixed_info = (uint8_t *)test_tls1_2_ms_seed;
	key_ex_args.output_sz = master_secret_len;
	key_ex_args.output = master_secret;

	err = hsm_key_exchange(key_mgmt_hdl, &key_ex_args);
	printf("\nhsm_key_exchange [TLS 1.2 Master Secret case #1.2] err: 0x%x\n\n", err);
	if (err != HSM_NO_ERROR)
		goto out;

	/* 4.1. Compute Premaster Secret with MbedTLS   */
	my_mbedtls_ecdh(HSM_KEY_SIZE_ECC_NIST_256, HSM_KEY_TYPE_ECC_NIST,
			fw_pub_key, sizeof(fw_pub_key),
			ecc_256_priv_key, sizeof(ecc_256_priv_key),
			mbedtls_premaster_secret,
			&mbedtls_premaster_secret_len);

	/* 4.2. Compute Mbed-TLS master secret */
	ret = my_mbedtls_tls12_prf(HSM_KEY_DERIVATION_TLS1_2_MASTER_SECRET_SHA256,
				   mbedtls_premaster_secret,
				   mbedtls_premaster_secret_len,
				   test_tls1_2_label_master_secret,
				   test_tls1_2_ms_seed + tls1_2_label_ms_len,
				   sizeof(test_tls1_2_ms_seed) - tls1_2_label_ms_len,
				   mbedtls_master_secret,
				   sizeof(mbedtls_master_secret));
	if (ret)
		goto out;

	/* 5. Compare Mbedt-TLS master secret with ELE FW master secret generated  */
	if (!memcmp(master_secret, mbedtls_master_secret, sizeof(master_secret_len)))
		printf("TLS 1.2 MS: Mbed-TLS validation. SUCCESS\n");
	else
		printf("TLS 1.2 MS: Mbed-TLS validation. FAILED\n");

out:
	/* 6. Delete the test Keys */
	delete_test_key(key_mgmt_hdl, fw_key_id, 0);
}

/**
 *    TLS 1.2 RFC 5246: Section 6.3
 *
 *    key_block = PRF(SecurityParameters.master_secret,
 *                    "key expansion",
 *                    SecurityParameters.server_random +
 *                    SecurityParameters.client_random);
 *
 *     The key_block is partitioned as follows:
 *
 *     client_write_MAC_key[SecurityParameters.mac_key_length]
 *     server_write_MAC_key[SecurityParameters.mac_key_length]
 *     client_write_key[SecurityParameters.enc_key_length]
 *     server_write_key[SecurityParameters.enc_key_length]
 *     client_write_IV[SecurityParameters.fixed_iv_length]
 *     server_write_IV[SecurityParameters.fixed_iv_length]
 *
 */
static void test_tls1_2_key_block(hsm_hdl_t key_store_hdl,
				  hsm_hdl_t key_mgmt_hdl,
				  uint32_t master_secret_key_id,
				  uint8_t *master_secret,
				  uint32_t master_secret_len)
{
	hsm_err_t err;
	in_content_tls1_2_key_block_args_t in_content;
	op_key_exchange_args_t key_ex_args;
	uint32_t client_write_mac_key_id;
	uint32_t server_write_mac_key_id;
	uint32_t client_write_key_id;
	uint32_t server_write_key_id;
	/**
	 * client write MAC key ID | server write MAC key ID |
	 * client write key ID | server write key ID
	 *
	 * 4 * Key ID size i.e. sizeof(uint32_t) = 16 bytes
	 */
	uint8_t output_key_ids[16] = {0};
	/**
	 * Test case specific:
	 * key_block size (keys only) = 2 * 32 (HMAC keys 256 bits) +
	 *                              2 * 16 (AES keys 128 bits)
	 */
	uint8_t key_block[96] = {0};
	/**
	 * Test case specific:
	 * key_block size (keys + iv):
	 *	2 * 32 (HMAC keys 256 bits) +
	 *	2 * 16 (AES keys 128 bits)
	 *	2 * 16 (AES 128 CBC - IV size)
	 */
	uint8_t mbedtls_tls1_2_key_block[128] = {0};
	uint32_t tls1_2_label_kb_len = strlen(test_tls1_2_label_key_expansion);
	uint32_t ret;

	printf("\nTLS 1.2 Key Block Secret:\n");
	printf("--------------------------\n");

	/* 1. Prepare Input Content for TLS 1.2 Key Block secrets */
	memset(&in_content, 0, sizeof(in_content_tls1_2_key_block_args_t));

	in_content.ver = 0x1;
	in_content.rsv = 0x0;
	in_content.keystore_id = TEST_KEYSTORE_ID;
	in_content.tls1_2_algo = HSM_KEY_DERIVATION_TLS1_2_KEY_BLOCK_SHA256;
	in_content.priv_key_id = master_secret_key_id;
	in_content.derived_key_type = HSM_KEY_TYPE_DERIVE; //Ignored
	in_content.ciphersuite_key_bits_size = HSM_KEY_SIZE_AES_128;
	in_content.derived_key_lifetime = HSM_SE_KEY_STORAGE_VOLATILE; //Ignored
	in_content.derived_key_usage = HSM_KEY_USAGE_DERIVE; //Ignored
	in_content.ciphersuite_algorithm = PERMITTED_ALGO_CBC_NO_PADDING;
	in_content.derived_key_lifecycle = 0x0; // Ignored by ELE. Set to Current
	in_content.derived_key_id = 0x0; // Ignored by ELE
	in_content.master_secret_len = 0x0;
	in_content.master_secret = NULL;

	/* 2.1. Derived TLS 1.2 Key Block keys stored in ELE FW. */
	memset(&key_ex_args, 0, sizeof(op_key_exchange_args_t));

	key_ex_args.flags = HSM_OP_KEY_EXCHANGE_FLAGS_INPUT_PLAINTEXT_CONTENT |
		HSM_OP_KEY_EXCHANGE_FLAGS_RETURN_KEY_IDS;
	key_ex_args.in_content_sz = sizeof(in_content);
	key_ex_args.in_content = (uint8_t *)(&in_content);
	key_ex_args.in_pub_buffer_sz = sizeof(ecc_256_pub_key);
	key_ex_args.in_pub_buffer = ecc_256_pub_key;
	key_ex_args.user_fixed_info_sz = sizeof(test_tls1_2_kb_seed);
	key_ex_args.user_fixed_info = (uint8_t *)test_tls1_2_kb_seed;
	key_ex_args.output_sz = sizeof(output_key_ids);
	key_ex_args.output = output_key_ids;

	err = hsm_key_exchange(key_mgmt_hdl, &key_ex_args);
	printf("\nhsm_key_exchange [TLS 1.2 Key Blocks case #1.1] err: 0x%x\n", err);
	printf("\t--Output Key IDs:\n");
	dump_hex(output_key_ids, sizeof(output_key_ids));

	if (err != HSM_NO_ERROR)
		return;

	/* 2.2. Extract Key IDs from output buffer, for MAC, Cipher op */
	client_write_mac_key_id = get_key_id_from_buffer(output_key_ids,
							 sizeof(output_key_ids));

	server_write_mac_key_id = get_key_id_from_buffer(output_key_ids + 4,
							 sizeof(output_key_ids) - 4);

	client_write_key_id = get_key_id_from_buffer(output_key_ids + 8,
						     sizeof(output_key_ids) - 8);

	server_write_key_id = get_key_id_from_buffer(output_key_ids + 12,
						     sizeof(output_key_ids) - 12);

	/* 2.3. Perform Crypto operations with the obtained keys*/
	test_tls1_2_kb_keys_hmac(key_store_hdl,
				 client_write_mac_key_id,
				 PERMITTED_ALGO_HMAC_SHA256);

	test_tls1_2_kb_keys_hmac(key_store_hdl,
				 server_write_mac_key_id,
				 PERMITTED_ALGO_HMAC_SHA256);

	test_tls1_2_kb_keys_cbc(key_store_hdl, client_write_key_id);
	test_tls1_2_kb_keys_cbc(key_store_hdl, server_write_key_id);

	/* 3.1. Export Derived TLS 1.2 Key Block from ELE FW. */
	memset(&key_ex_args, 0, sizeof(op_key_exchange_args_t));

	key_ex_args.flags = HSM_OP_KEY_EXCHANGE_FLAGS_INPUT_PLAINTEXT_CONTENT |
			    HSM_OP_KEY_EXCHANGE_FLAGS_RETURN_OUTPUT;
	key_ex_args.in_content_sz = sizeof(in_content);
	key_ex_args.in_content = (uint8_t *)(&in_content);
	key_ex_args.in_pub_buffer_sz = sizeof(ecc_256_pub_key);
	key_ex_args.in_pub_buffer = ecc_256_pub_key;
	key_ex_args.user_fixed_info_sz = sizeof(test_tls1_2_kb_seed);
	key_ex_args.user_fixed_info = (uint8_t *)test_tls1_2_kb_seed;
	key_ex_args.output_sz = sizeof(key_block);
	key_ex_args.output = key_block;

	err = hsm_key_exchange(key_mgmt_hdl, &key_ex_args);
	printf("\nhsm_key_exchange [TLS 1.2 Key Blocks case #1.2] err: 0x%x\n\n", err);
	if (err != HSM_NO_ERROR)
		goto out;

	/* 4. Compute Mbed-TLS Key Block  */
	ret = my_mbedtls_tls12_prf(HSM_KEY_DERIVATION_TLS1_2_KEY_BLOCK_SHA256,
				   master_secret,
				   master_secret_len,
				   test_tls1_2_label_key_expansion,
				   test_tls1_2_kb_seed + tls1_2_label_kb_len,
				   sizeof(test_tls1_2_kb_seed) - tls1_2_label_kb_len,
				   mbedtls_tls1_2_key_block,
				   sizeof(mbedtls_tls1_2_key_block));

	if (ret)
		goto out;

	/* 5. Compare Mbed-TLS Key Block with ELE FW TLS 1.2 Key Block */
	if (!memcmp(key_block, mbedtls_tls1_2_key_block, sizeof(key_block)))
		printf("TLS 1.2 KB: Mbed-TLS validation. SUCCESS\n");
	else
		printf("TLS 1.2 KB: Mbed-TLS validation. FAILED\n");

out:
	/* 6. Delete the test Keys */
	delete_test_key(key_mgmt_hdl, client_write_mac_key_id, 0);
	delete_test_key(key_mgmt_hdl, server_write_mac_key_id, 0);
	delete_test_key(key_mgmt_hdl, client_write_key_id, 0);
	delete_test_key(key_mgmt_hdl, server_write_key_id, 0);
}

static void test_tls1_2_iv(hsm_hdl_t key_mgmt_hdl,
			   uint32_t master_secret_key_id,
			   uint8_t *master_secret,
			   uint32_t master_secret_len)

{
	hsm_err_t err;
	in_content_tls1_2_iv_args_t in_content;
	op_key_exchange_args_t key_ex_args;
	uint8_t output_ivs[32] = {0}; // client write IV | server write IV
	uint8_t mbedtls_tls1_2_kb_iv[128] = {0};
	uint32_t tls1_2_label_kb_len = strlen(test_tls1_2_label_key_expansion);
	uint8_t iv_offset = 96;
	uint32_t ret;

	printf("\nTLS 1.2 IVs:\n");
	printf("--------------------------\n");

	/* 1. Prepare Input Content for TLS 1.2 IVs */
	memset(&in_content, 0, sizeof(in_content_tls1_2_iv_args_t));

	in_content.ver = 0x1;
	in_content.rsv = 0x0;
	in_content.keystore_id = TEST_KEYSTORE_ID;
	in_content.tls1_2_algo = HSM_KEY_DERIVATION_TLS1_2_IV_SHA256;
	in_content.priv_key_id = master_secret_key_id;
	in_content.derived_key_type = 0x0;      //Ignored
	in_content.ciphersuite_key_bits_size = HSM_KEY_SIZE_AES_128;
	in_content.derived_key_lifetime = 0x0;  //Ignored
	in_content.derived_key_usage = 0x0;     //Ignored
	in_content.ciphersuite_algorithm = PERMITTED_ALGO_CBC_NO_PADDING;
	in_content.derived_key_lifecycle = 0x0; // Ignored by ELE. Set to Current
	in_content.derived_key_id = 0x0;        // Ignored by ELE
	in_content.master_secret_len = 0x0;     // Optional if Master Key ID used
	in_content.master_secret = NULL;        // Optional if Master Key ID used

	/* 2. Export ELE FW generated TLS 1.2 IVs */
	memset(&key_ex_args, 0, sizeof(op_key_exchange_args_t));

	key_ex_args.flags = HSM_OP_KEY_EXCHANGE_FLAGS_INPUT_PLAINTEXT_CONTENT |
		HSM_OP_KEY_EXCHANGE_FLAGS_RETURN_OUTPUT;
	key_ex_args.in_content_sz = sizeof(in_content);
	key_ex_args.in_content = (uint8_t *)(&in_content);
	key_ex_args.in_pub_buffer_sz = sizeof(ecc_256_pub_key);
	key_ex_args.in_pub_buffer = ecc_256_pub_key;
	key_ex_args.user_fixed_info_sz = sizeof(test_tls1_2_kb_seed);
	key_ex_args.user_fixed_info = (uint8_t *)test_tls1_2_kb_seed;
	key_ex_args.output_sz = sizeof(output_ivs);
	key_ex_args.output = output_ivs;

	err = hsm_key_exchange(key_mgmt_hdl, &key_ex_args);
	printf("\nhsm_key_exchange [TLS 1.2 IVs] err: 0x%x\n\n", err);
	if (err != HSM_NO_ERROR)
		return;

	/* 3. Compute Mbed-TLS TLS 1.2 IVs */
	ret = my_mbedtls_tls12_prf(HSM_KEY_DERIVATION_TLS1_2_IV_SHA256,
				   master_secret,
				   master_secret_len,
				   test_tls1_2_label_key_expansion,
				   test_tls1_2_kb_seed + tls1_2_label_kb_len,
				   sizeof(test_tls1_2_kb_seed) - tls1_2_label_kb_len,
				   mbedtls_tls1_2_kb_iv,
				   sizeof(mbedtls_tls1_2_kb_iv));
	if (ret)
		return;

	/**
	 *  4. Compare Mbed-TLS TLS 1.2 IVs with ELE FW generated TLS 1.2 IVs
	 *
	 *  Key Block = Keys + IVs
	 *
	 *  IV offset:
	 *  key_block keys size = 2 * 32 (HMAC key 256 bits) + 2 * 16 (AES key 128 bits)
	 */
	if (!memcmp(output_ivs, mbedtls_tls1_2_kb_iv + iv_offset, sizeof(output_ivs)))
		printf("TLS 1.2 IVs: Mbed-TLS validation. SUCCESS\n");
	else
		printf("TLS 1.2 IVs: Mbed-TLS validation. FAILED\n");
}

/**
 * TLS 1.2 tests for:
 *	- "Master Secret",
 *	- "Key Block",
 *	  -- Client / Server write MAC keys
 *        -- Client / Server write Keys
 *	- "IV"
 *        -- Client / Server IVs
 */
void key_exchange_test_tls1_2(hsm_hdl_t key_store_hdl, hsm_hdl_t key_mgmt_hdl)
{
	hsm_err_t err;
	uint32_t master_secret_key_id = 0;
	uint8_t master_secret[BITS_TO_BYTES(HSM_KEY_SIZE_DERIVE_384)];
	uint8_t master_secret_len = sizeof(master_secret);

	printf("\n-----------------------------------------------------\n");
	printf("Key Exchange API tests - TLS 1.2");
	printf("\n-----------------------------------------------------\n");

	memset(master_secret, 0, master_secret_len);

	test_tls1_2_master_secret(key_mgmt_hdl, &master_secret_key_id,
				  master_secret, master_secret_len);

	test_tls1_2_key_block(key_store_hdl, key_mgmt_hdl, master_secret_key_id,
			      master_secret, master_secret_len);

	test_tls1_2_iv(key_mgmt_hdl, master_secret_key_id,
		       master_secret, master_secret_len);

	/* Delete the test keys */
	delete_test_key(key_mgmt_hdl, master_secret_key_id, 0);

	printf("\n-----------------------------------------------------\n");
	printf("Test Complete");
	printf("\n-----------------------------------------------------\n");
}
#endif
