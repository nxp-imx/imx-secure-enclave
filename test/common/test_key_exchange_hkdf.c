// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#include <stdio.h>

#include "test_common.h"
#include "hsm_api.h"

#ifdef PSA_COMPLIANT

#include "mbedtls_utils.h"

/* HKDF Expand test helper function to generate key (PRK ID) for the operation. */
static void key_exchange_test_hkdf_expand_helper(hsm_hdl_t key_mgmt_hdl,
						 uint32_t *key_id)
{
	hsm_err_t err;
	in_content_tls13_args_t in_content = {0};
	op_key_exchange_args_t key_ex_args = {0};

	/*************** HKDF Expand Helper - Generate PRK ID *****************/

	/* HKDF label related variables */
	unsigned char hkdf_label[TEST_TLS1_3_HKDF_LABEL_MAX_LEN];
	uint16_t hkdf_label_len = 0;
	/* expanded key len - 32 bytes */
	uint16_t length = BITS_TO_BYTES(HSM_KEY_SIZE_DERIVE_256);
	const unsigned char *label = test_tls13_label_ext_binder;
	uint8_t label_len = sizeof(test_tls13_label_ext_binder);
	const unsigned char *context = context_buffer;
	uint8_t context_len = sizeof(context_buffer);

	if (!key_id)
		return;

	printf("\nTLS 1.3 Early Secret as PRK\n");
	printf("-----------------------------\n");

	/* 1. Prepare Input Plaintext Context, without optional PSK */
	memset(&in_content, 0, sizeof(in_content_tls13_args_t));

	in_content.ver = 0x1;
	in_content.rsv = 0x0;
	in_content.keystore_id = TEST_KEYSTORE_ID;
	in_content.tls1_3_algo = HSM_KEY_DERIVATION_TLS1_3_EARLY_SECRET_SHA256;
	in_content.priv_key_id = 0x0; // Ignored for Early Secrets.
	in_content.derived_key_type = HSM_KEY_TYPE_DERIVE;
	in_content.derived_key_bits_size = HSM_KEY_SIZE_DERIVE_256;
	in_content.derived_key_lifetime = HSM_SE_KEY_STORAGE_VOLATILE; // Volatile
	in_content.derived_key_usage = HSM_KEY_USAGE_DERIVE;
	in_content.derived_key_permitted_algo = HSM_KEY_DERIVATION_HKDF_EXPAND_SHA256;
	in_content.derived_key_lifecycle = 0x0; // Current
	in_content.derived_key_id = 0x0; // Volatile Key, so ID chosen by FW
	in_content.psk_len = 0x0; // Optional PSK not used.

	/* 2. Prepare User Fixed Info or HKDF label */
	memset(hkdf_label, 0, sizeof(hkdf_label));

	tls13_hkdf_label_encode(length,
				label, label_len,
				context, context_len,
				hkdf_label, &hkdf_label_len);

	/* 3. Case 1.1. Derived Key stored in ELE FW. */
	memset(&key_ex_args, 0, sizeof(op_key_exchange_args_t));

	key_ex_args.flags = HSM_OP_KEY_EXCHANGE_FLAGS_INPUT_PLAINTEXT_CONTENT;
	key_ex_args.in_content_sz = sizeof(in_content_tls13_args_t);
	key_ex_args.in_content = (uint8_t *)(&in_content);
	key_ex_args.in_pub_buffer_sz = 0x0;
	key_ex_args.in_pub_buffer = NULL;
	key_ex_args.user_fixed_info_sz = hkdf_label_len;
	key_ex_args.user_fixed_info = (uint8_t *)hkdf_label;
	key_ex_args.output_sz = 0;
	key_ex_args.output = NULL;

	err = hsm_key_exchange(key_mgmt_hdl, &key_ex_args);
	printf("\nhsm_key_exchange [TLS 1.3 ES case #1.1] err: 0x%x\n", err);
	printf("\t--Derived PRK ID: 0x%x\n", key_ex_args.out_derived_key_id);
	printf("\t--Salt Size: 0x%x\n", key_ex_args.out_salt_sz);
	if (err != HSM_NO_ERROR)
		return;

	*key_id = key_ex_args.out_derived_key_id;
}

void key_exchange_test_hkdf_expand(hsm_hdl_t key_mgmt_hdl)
{
	hsm_err_t err;
	in_content_hkdf_args_t in_content = {0};
	op_key_exchange_args_t key_ex_args = {0};
	op_delete_key_args_t del_args = {0};
	uint32_t prk_id = 0; //PRK ID, ELE FW
	uint32_t output_key_buffer[TEST_HKDF_EXPAND_MAX_KEY_SIZE];

	printf("\n-----------------------------------------------------\n");
	printf("Key Exchange API test - HKDF (Expand) ");
	printf("\n-----------------------------------------------------\n");

	/* 1. Get PRK ID */
	key_exchange_test_hkdf_expand_helper(key_mgmt_hdl, &prk_id);

	printf("\nHKDF Expand\n");
	printf("-------------\n");

	/* 2. Prepare Input Plaintext Content, with PRK ID */
	memset(&in_content, 0, sizeof(in_content_hkdf_args_t));

	in_content.ver = 0x1;
	in_content.rsv = 0x0;
	in_content.keystore_id = TEST_KEYSTORE_ID;
	in_content.hkdf_algo = HSM_KEY_DERIVATION_HKDF_EXPAND_SHA256;
	in_content.key_id = prk_id;
	in_content.derived_key_type = HSM_KEY_TYPE_AES;
	in_content.derived_key_bits_size = HSM_KEY_SIZE_AES_256;
	in_content.derived_key_lifetime = HSM_SE_KEY_STORAGE_VOLATILE;
	in_content.derived_key_usage = HSM_KEY_USAGE_ENCRYPT | HSM_KEY_USAGE_DECRYPT;
	in_content.derived_key_permitted_algo = PERMITTED_ALGO_ALL_CIPHER;
	in_content.derived_key_lifecycle = 0x0; // Current
	in_content.derived_key_id = 0x0; // Volatile Key, so ID chosen by FW
	in_content.buffer_len = 0x0; // PRK Buffer not used.

	/* 3. Case 1.1. Derived Key stored in ELE FW */
	memset(&key_ex_args, 0, sizeof(op_key_exchange_args_t));

	key_ex_args.flags = HSM_OP_KEY_EXCHANGE_FLAGS_INPUT_PLAINTEXT_CONTENT;
	key_ex_args.in_content_sz = sizeof(in_content_hkdf_args_t);
	key_ex_args.in_content = (uint8_t *)(&in_content);
	key_ex_args.in_pub_buffer_sz = 0x0;
	key_ex_args.in_pub_buffer = NULL;
	key_ex_args.user_fixed_info_sz = sizeof(user_fixed_info);
	key_ex_args.user_fixed_info = user_fixed_info;
	key_ex_args.output_sz = 0;
	key_ex_args.output = NULL;

	err = hsm_key_exchange(key_mgmt_hdl, &key_ex_args);
	printf("\nhsm_key_exchange [HKDF Expand case #1.1] err: 0x%x\n", err);
	printf("\t--Derived Key ID: 0x%x\n", key_ex_args.out_derived_key_id);
	printf("\t--Salt Size: 0x%x\n", key_ex_args.out_salt_sz);
	if (err != HSM_NO_ERROR)
		goto out;

	/* 4. Delete Derived Key */
	memset(&del_args, 0, sizeof(del_args));

	del_args.key_identifier = key_ex_args.out_derived_key_id;
	del_args.flags = 0;
	err = hsm_delete_key(key_mgmt_hdl, &del_args);
	if (err != HSM_NO_ERROR)
		printf("hsm_delete_key (Derived #1) ret: 0x%x\n", err);

	/* 5. Case 1.2. Export Derived/Output Key Buffer */
	memset(&key_ex_args, 0, sizeof(op_key_exchange_args_t));
	memset(output_key_buffer, 0, sizeof(output_key_buffer));

	key_ex_args.flags = HSM_OP_KEY_EXCHANGE_FLAGS_INPUT_PLAINTEXT_CONTENT |
			    HSM_OP_KEY_EXCHANGE_FLAGS_RETURN_OUTPUT;
	key_ex_args.in_content_sz = sizeof(in_content_hkdf_args_t);
	key_ex_args.in_content = (uint8_t *)(&in_content);
	key_ex_args.in_pub_buffer_sz = 0x0;
	key_ex_args.in_pub_buffer = NULL;
	key_ex_args.user_fixed_info_sz = sizeof(user_fixed_info);
	key_ex_args.user_fixed_info = user_fixed_info;
	key_ex_args.output_sz = BITS_TO_BYTES(HSM_KEY_SIZE_AES_256);
	key_ex_args.output = (uint8_t *)output_key_buffer;

	err = hsm_key_exchange(key_mgmt_hdl, &key_ex_args);
	printf("\nhsm_key_exchange [HKDF Expand case #1.2] err: 0x%x\n", err);
	printf("\t--Derived Key ID: 0x%x\n", key_ex_args.out_derived_key_id);
	printf("\t--Salt Size: 0x%x\n", key_ex_args.out_salt_sz);
	printf("\n--Derived Key Buffer:\n");
	dump_hex(key_ex_args.output, key_ex_args.output_sz);

	if (err != HSM_NO_ERROR)
		goto out;

	/* 6. Delete PRK */
	memset(&del_args, 0, sizeof(del_args));

	del_args.key_identifier = prk_id;
	del_args.flags = 0;
	err = hsm_delete_key(key_mgmt_hdl, &del_args);
	if (err != HSM_NO_ERROR)
		printf("hsm_delete_key (PRK) ret: 0x%x\n", err);

out:
	printf("\n-----------------------------------------------------\n");
	printf("Test Complete");
	printf("\n-----------------------------------------------------\n");
}

/* Key Exchange - HKDF operation */
static void key_exchange_test_hkdf(hsm_hdl_t key_store_hdl,
				   hsm_hdl_t key_mgmt_hdl,
				   hsm_op_key_derivation_algo_t hkdf_algo,
				   bool is_plaintext_ikm)
{
	hsm_err_t err;
	op_generate_key_args_t key_gen_args = {0};
	op_key_exchange_args_t key_ex_args = {0};
	op_cipher_one_go_args_t cipher_args = {0};
	op_delete_key_args_t del_args = {0};
	in_content_hkdf_args_t *in_content = NULL;
	uint32_t in_content_sz;
	hsm_bit_key_sz_t fw_key_bit_sz;
	hsm_permitted_algo_t test_key_permitted_algo;
	uint32_t in_pub_buffer_sz;
	uint8_t *in_pub_buffer;
	uint16_t fw_pub_key_sz;
	uint8_t fw_pub_key[96] = {0};
	uint8_t *peer_pub_key;
	uint8_t peer_pub_key_sz;
	uint8_t *peer_priv_key;
	uint8_t peer_priv_key_sz;
	uint32_t key_id = 0;
	uint32_t derived_key_id = 0;
	uint8_t *mbedtls_ikm = NULL;
	uint8_t mbedtls_ikm_len = 0;
	uint8_t mbedtls_ecdh_ikm[48] = {0};
	uint32_t mbedtls_ecdh_ikm_len = sizeof(mbedtls_ecdh_ikm);
	uint8_t output_key_buffer[TEST_HKDF_FULL_MAX_KEY_SIZE];
	uint8_t mbedtls_hkdf_okm[TEST_HKDF_FULL_MAX_KEY_SIZE];
	uint8_t ciphered_data[32] = {0};
	uint8_t mbedtls_ciphered_data[32] = {0};
	uint32_t ret;

	if (hkdf_algo == HSM_KEY_DERIVATION_HKDF_SHA256) {
		fw_pub_key_sz = 2 * BITS_TO_BYTES(HSM_KEY_SIZE_ECC_NIST_256);
		fw_key_bit_sz = HSM_KEY_SIZE_ECC_NIST_256;
		test_key_permitted_algo = PERMITTED_ALGO_HKDF_EXTRACT_SHA256;
		peer_pub_key = ecc_256_pub_key;
		peer_pub_key_sz = sizeof(ecc_256_pub_key);
		peer_priv_key = ecc_256_priv_key;
		peer_priv_key_sz = sizeof(ecc_256_priv_key);
	} else {
		fw_pub_key_sz = 2 * BITS_TO_BYTES(HSM_KEY_SIZE_ECC_NIST_384);
		fw_key_bit_sz = HSM_KEY_SIZE_ECC_NIST_384;
		test_key_permitted_algo = PERMITTED_ALGO_HKDF_EXTRACT_SHA384;
		peer_pub_key = ecc_384_pub_key;
		peer_pub_key_sz = sizeof(ecc_384_pub_key);
		peer_priv_key = ecc_384_priv_key;
		peer_priv_key_sz = sizeof(ecc_384_priv_key);
	}

	/* Select Input Public Buffer, depending on whether input is Plaintext IKM
	 * or Peer Public Key
	 */
	if (is_plaintext_ikm) {
		in_pub_buffer_sz = sizeof(hkdf_ikm);
		in_pub_buffer = (uint8_t *)hkdf_ikm;
	} else {
		in_pub_buffer_sz = peer_pub_key_sz;
		in_pub_buffer = peer_pub_key;

		/* Generate key pair which will be used to generate ECDH IKM */
		memset(&key_gen_args, 0, sizeof(op_generate_key_args_t));

		key_gen_args.key_identifier = &key_id;
		key_gen_args.key_group = 40;
		key_gen_args.key_lifetime = HSM_SE_KEY_STORAGE_VOLATILE;
		key_gen_args.key_usage = HSM_KEY_USAGE_DERIVE;
		key_gen_args.permitted_algo = test_key_permitted_algo;
		key_gen_args.flags = 0x0;
		key_gen_args.key_type = HSM_KEY_TYPE_ECC_NIST;
		key_gen_args.bit_key_sz = fw_key_bit_sz;
		key_gen_args.key_lifecycle = 0x0; // Current Device Lifecycle
		key_gen_args.out_key = fw_pub_key;
		key_gen_args.out_size = fw_pub_key_sz;

		err = hsm_generate_key(key_mgmt_hdl, &key_gen_args);
		if (err != HSM_NO_ERROR) {
			printf("\nhsm_generate_key err: 0x%x\n", err);
			goto out;
		}
	}

	/* Prepare Input Plaintext Content */
	in_content_sz = sizeof(in_content_hkdf_args_t) + sizeof(hkdf_salt);
	in_content = (in_content_hkdf_args_t *)malloc(in_content_sz);

	if (!in_content) {
		printf("Failed to allocated memory");
		goto out;
	}

	memset(in_content, 0, in_content_sz);

	in_content->ver = 0x1;
	in_content->rsv = 0x0;
	in_content->keystore_id = TEST_KEYSTORE_ID;
	in_content->hkdf_algo = hkdf_algo;
	in_content->key_id = key_id;
	in_content->derived_key_type = HSM_KEY_TYPE_AES;
	in_content->derived_key_bits_size = HSM_KEY_SIZE_AES_256;
	in_content->derived_key_lifetime = HSM_SE_KEY_STORAGE_VOLATILE;
	in_content->derived_key_usage = HSM_KEY_USAGE_ENCRYPT | HSM_KEY_USAGE_DECRYPT;
	in_content->derived_key_permitted_algo = PERMITTED_ALGO_ALL_CIPHER;
	in_content->derived_key_lifecycle = 0x0; // Current lifecycle
	in_content->derived_key_id = 0x0; // Volatile Key, so ID chosen by FW
	in_content->buffer_len = sizeof(hkdf_salt);
	memcpy(in_content->buffer, hkdf_salt, in_content->buffer_len);

	/* Case #1. Derived Key stored in ELE FW */
	memset(&key_ex_args, 0, sizeof(op_key_exchange_args_t));

	key_ex_args.flags = HSM_OP_KEY_EXCHANGE_FLAGS_INPUT_PLAINTEXT_CONTENT;
	key_ex_args.in_content_sz = in_content_sz;
	key_ex_args.in_content = (uint8_t *)(in_content);
	key_ex_args.in_pub_buffer_sz = in_pub_buffer_sz;
	key_ex_args.in_pub_buffer = in_pub_buffer;
	key_ex_args.user_fixed_info_sz = sizeof(hkdf_info);
	key_ex_args.user_fixed_info = (uint8_t *)hkdf_info;
	key_ex_args.output_sz = 0;
	key_ex_args.output = NULL;

	err = hsm_key_exchange(key_mgmt_hdl, &key_ex_args);
	printf("\nhsm_key_exchange [HKDF case #1] err: 0x%x ", err);
	printf("[Derived Key ID: 0x%x]", key_ex_args.out_derived_key_id);
	if (err != HSM_NO_ERROR)
		goto out;

	derived_key_id = key_ex_args.out_derived_key_id;

	/* Case #2. Export Derived/Output Key Buffer */
	memset(&key_ex_args, 0, sizeof(op_key_exchange_args_t));
	memset(output_key_buffer, 0, sizeof(output_key_buffer));

	key_ex_args.flags = HSM_OP_KEY_EXCHANGE_FLAGS_INPUT_PLAINTEXT_CONTENT |
			    HSM_OP_KEY_EXCHANGE_FLAGS_RETURN_OUTPUT;
	key_ex_args.in_content_sz = in_content_sz;
	key_ex_args.in_content = (uint8_t *)in_content;
	key_ex_args.in_pub_buffer_sz = in_pub_buffer_sz;
	key_ex_args.in_pub_buffer = in_pub_buffer;
	key_ex_args.user_fixed_info_sz = sizeof(hkdf_info);
	key_ex_args.user_fixed_info = (uint8_t *)hkdf_info;
	key_ex_args.output_sz = BITS_TO_BYTES(HSM_KEY_SIZE_AES_256);
	key_ex_args.output = (uint8_t *)output_key_buffer;

	err = hsm_key_exchange(key_mgmt_hdl, &key_ex_args);
	printf("\nhsm_key_exchange [HKDF case #2] err: 0x%x ", err);
	printf("[Derived Key ID: 0x%x]", key_ex_args.out_derived_key_id);

	if (err != HSM_NO_ERROR)
		goto out;

	if (is_plaintext_ikm) {
		mbedtls_ikm = hkdf_ikm;
		mbedtls_ikm_len = sizeof(hkdf_ikm);
	} else {
		/* Compute ECDH IKM with MbedTLS   */
		ret = my_mbedtls_ecdh(fw_key_bit_sz, HSM_KEY_TYPE_ECC_NIST,
				      fw_pub_key, fw_pub_key_sz,
				      peer_priv_key, peer_priv_key_sz,
				      mbedtls_ecdh_ikm, &mbedtls_ecdh_ikm_len);
		if (ret)
			goto out;

		mbedtls_ikm = mbedtls_ecdh_ikm;
		mbedtls_ikm_len = mbedtls_ecdh_ikm_len;
	}

	/* Derive key using Mbed-TLS, with same set of parameters */
	memset(mbedtls_hkdf_okm, 0x0, sizeof(mbedtls_hkdf_okm));

	ret = my_mbedtls_hkdf(HSM_HASH_ALGO_FROM_ALGO(hkdf_algo),
			      mbedtls_ikm, mbedtls_ikm_len,
			      hkdf_salt, sizeof(hkdf_salt),
			      hkdf_info, sizeof(hkdf_info),
			      mbedtls_hkdf_okm, BITS_TO_BYTES(HSM_KEY_SIZE_AES_256));
	if (ret)
		goto out;

	/* Cipher API op using FW Derived Key ID */
	cipher_args.key_identifier = derived_key_id;
	cipher_args.cipher_algo = HSM_CIPHER_ONE_GO_ALGO_CBC;
	cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_ENCRYPT;
	cipher_args.input = test_msg;
	cipher_args.output = ciphered_data;
	cipher_args.input_size = sizeof(test_msg);
	cipher_args.output_size = sizeof(ciphered_data);
	cipher_args.iv = iv;
	cipher_args.iv_size = sizeof(iv);

	err = hsm_do_cipher(key_store_hdl, &cipher_args);
	if (err != HSM_NO_ERROR) {
		printf("hsm_cipher_one_go ret:0x%x\n", err);
		goto out;
	}

	/* Mbed-TLS cipher operation using Mbed-TLS Derived Key */
	ret = my_mbedtls_aes_cbc(HSM_KEY_SIZE_AES_256, mbedtls_hkdf_okm,
				 HSM_CIPHER_ONE_GO_FLAGS_ENCRYPT,
				 test_msg, sizeof(test_msg),
				 mbedtls_ciphered_data, iv);
	if (ret)
		goto out;

	/* Compare Mbedt-TLS Enc Data with ELE FW generated Enc Data using Key ID */
	if (!memcmp(ciphered_data, mbedtls_ciphered_data, sizeof(ciphered_data)))
		printf("\nHKDF: Derived Key ID: Mbed-TLS validation. SUCCESS");
	else
		printf("\nHKDF: Derived Key ID: Mbed-TLS validation. FAILED");

	/* Compare Mbedt-TLS OKM  with ELE FW Derived Key  */
	if (!memcmp(key_ex_args.output, mbedtls_hkdf_okm, key_ex_args.output_sz))
		printf("\nHKDF: Derived Key buffer: Mbed-TLS validation. SUCCESS\n");
	else
		printf("\nHKDF: Derived Key Buffer: Mbed-TLS validation. FAILED\n");

	/* Delete ELE FW Derived Key ID */
	memset(&del_args, 0, sizeof(del_args));

	del_args.key_identifier = derived_key_id;
	err = hsm_delete_key(key_mgmt_hdl, &del_args);
	if (err != HSM_NO_ERROR)
		printf("hsm_delete_key ret: 0x%x\n", err);

	/* Delete the Key, if used for generating ECDH IKM */
	if (key_id) {
		memset(&del_args, 0, sizeof(del_args));

		del_args.key_identifier = key_id;
		err = hsm_delete_key(key_mgmt_hdl, &del_args);
		if (err != HSM_NO_ERROR)
			printf("hsm_delete_key ret: 0x%x\n", err);
	}
out:
	if (in_content)
		free(in_content);
}

void key_exchange_test_hkdf_full(hsm_hdl_t key_store_hdl, hsm_hdl_t key_mgmt_hdl)
{
	printf("\n-----------------------------------------------------\n");
	printf("Key Exchange API test - HKDF");
	printf("\n-----------------------------------------------------\n");

	printf("\nHSM_KEY_DERIVATION_HKDF_SHA256 - Plaintext IKM:\n");
	key_exchange_test_hkdf(key_store_hdl,
			       key_mgmt_hdl,
			       HSM_KEY_DERIVATION_HKDF_SHA256,
			       true);

	printf("\n\nHSM_KEY_DERIVATION_HKDF_SHA384 - Plaintext IKM:\n");
	key_exchange_test_hkdf(key_store_hdl,
			       key_mgmt_hdl,
			       HSM_KEY_DERIVATION_HKDF_SHA384,
			       true);

	printf("\n\nHSM_KEY_DERIVATION_HKDF_SHA256 - Input Peer Public Key:\n");
	key_exchange_test_hkdf(key_store_hdl,
			       key_mgmt_hdl,
			       HSM_KEY_DERIVATION_HKDF_SHA256,
			       false);

	printf("\n\nHSM_KEY_DERIVATION_HKDF_SHA384 - Input Peer Public Key:\n");
	key_exchange_test_hkdf(key_store_hdl,
			       key_mgmt_hdl,
			       HSM_KEY_DERIVATION_HKDF_SHA384,
			       false);

	printf("\n-----------------------------------------------------\n");
	printf("Test Complete");
	printf("\n-----------------------------------------------------\n");
};
#endif
