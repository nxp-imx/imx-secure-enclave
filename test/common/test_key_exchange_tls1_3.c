// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024-2026 NXP
 */

#include <stdio.h>

#include "test_common.h"
#include "hsm_api.h"

#ifdef PSA_COMPLIANT
#include "mbedtls_utils.h"
#include "mbedtls_test.h"

/* Dump HEX buffer byte-by-byte */
void dump_hex(uint8_t buf[], uint32_t size)
{
	for (uint32_t i = 0; i < size; i++) {
		if (i != 0 && (i % 16 == 0))
			printf("\n");
		printf("%02x ", buf[i]);
	}
	printf("\n");
}

/**
 * HkdfLabel is specified as below, in the RFC 8446 section 7.1:
 *
 *       struct {
 *          uint16 length = Length;
 *          opaque label<7..255> = "tls13 " + Label;
 *          opaque context<0..255> = Context;
 *      } HkdfLabel;
 *
 */
static uint16_t tls13_hkdf_label_len_calc(uint8_t total_label_len, uint8_t context_len)
{
	uint16_t hkdf_label_len = 0;

	/* length: Length of the expanded key material */
	hkdf_label_len += TEST_TLS1_3_HKDF_LABEL_KEY_EXPANSION_LEN_FIELD_SZ;
	/**
	 * total_lable_len: sizeof( "tls13 " + label), must be < TEST_TLS1_3_LABEL_MAX_LEN
	 *
	 * label e.g. "res binder", "ext binder", "c hs traffic", "c ap traffic", etc.
	 */
	hkdf_label_len += TEST_TLS1_3_HKDF_LABEL_LABEL_LEN_FIELD_SZ + total_label_len;
	/**
	 * context_len: context buffer len, must be <= TEST_TLS1_3_HKDF_LABEL_CTX_MAX_LEN
	 * SHA224 --> 28 bytes,
	 * SHA256 --> 32 bytes,
	 * SHA384 --> 48 bytes,
	 * SHA512 --> 64 bytes,
	 */
	hkdf_label_len += TEST_TLS1_3_HKDF_LABEL_CTX_LEN_FIELD_SZ + context_len;

	return hkdf_label_len;
}

/**
 * The function prepares the HKDF label for TLS 1.3 following RFC 8446 section 7.1
 *
 * length: length of expanded key (in bytes)
 * label: label without "tls13 "
 * label_len : length of label (in bytes)
 * context: transcript hash
 * context: length of transcript hash (in bytes)
 * hkdf_label: output buffer for HKDF label of min. TEST_TLS1_3_HKDF_LABEL_MAX_LEN size
 * hkdf_label_len: actual length of the output HKDF label
 *
 */
void tls13_hkdf_label_encode(uint16_t length,
			     const unsigned char *label, uint8_t label_len,
			     const unsigned char *context, uint8_t context_len,
			     unsigned char *hkdf_label, uint16_t *hkdf_label_len)
{
	uint16_t total_label_len;
	uint16_t loc_hkdf_label_len;
	unsigned char *hkdf_label_p;

	if (!label || !hkdf_label || !hkdf_label_len) {
		printf("HKDF-Label-Encode Failed: Invalid arguments");
		return;
	}

	if (length > TEST_TLS1_3_HKDF_LABEL_KEY_EXPANSION_MAX_LEN) {
		printf("\nHKDF-Label-Encode Failed: Key Expansion len must be < %u\n",
		       TEST_TLS1_3_HKDF_LABEL_KEY_EXPANSION_MAX_LEN);
		return;
	}

	total_label_len = sizeof(test_tls13_label_prefix) + label_len;
	loc_hkdf_label_len = tls13_hkdf_label_len_calc(total_label_len,
						       context_len);

	hkdf_label_p = hkdf_label;

	/* Add Key Expansion Length,  */
	*hkdf_label_p = 0x0;
	hkdf_label_p++;
	*hkdf_label_p = (uint8_t)length;
	hkdf_label_p++;

	/* Add total label length */
	*hkdf_label_p = total_label_len;
	hkdf_label_p++;

	/* Add label prefix */
	memcpy(hkdf_label_p, test_tls13_label_prefix, sizeof(test_tls13_label_prefix));
	hkdf_label_p += sizeof(test_tls13_label_prefix);

	/* Add label */
	memcpy(hkdf_label_p, label, label_len);
	hkdf_label_p += label_len;

	/* Add context length */
	*hkdf_label_p = context_len;
	hkdf_label_p++;

	/* Add context */
	if (context_len && context)
		memcpy(hkdf_label_p, context, context_len);

	*hkdf_label_len = loc_hkdf_label_len;
}

/**
 * RFC 8446 section 7.1 Part-1 Early Secrets
 *
 *            0
 *            |
 *            v
 *  PSK ->  HKDF-Extract = Early Secret
 *            |
 *             |
 *            +-----> Derive-Secret(., "ext binder" | "res binder", "")
 *            |                     = binder_key
 *            |
 *            +-----> Derive-Secret(., "c e traffic", ClientHello)
 *            |                     = client_early_traffic_secret
 *            |
 *            +-----> Derive-Secret(., "e exp master", ClientHello)
 *            |                     = early_exporter_master_secret
 *            v
 *      Derive-Secret(., "derived", "")
 *            |
 *            v
 */
static void test_tls1_3_early_secrets(hsm_hdl_t key_mgmt_hdl,
				      uint32_t tls1_3_key_permitted_algo,
				      uint32_t tls1_3_es_algo,
				      uint32_t *test_key_id,
				      uint32_t key_store_id)
{
	hsm_err_t err;
	in_content_tls13_args_t in_content = {0};
	op_key_exchange_args_t key_ex_args = {0};
	op_delete_key_args_t del_args = {0};
	uint32_t key_id = 0; //Private Key ID, ELE FW
	uint32_t output_key_buffer[TEST_TLS1_3_DERIVED_MAX_KEY_SIZE];
	uint32_t hash_algo_size;
	uint32_t psk_id = 0;
	uint32_t psk_bit_key_size;

	/*********************Early Secrets - EXT Binder *********************/

	/* HKDF label related variables */
	unsigned char hkdf_label[TEST_TLS1_3_HKDF_LABEL_MAX_LEN];
	uint16_t hkdf_label_len = 0;
	uint16_t length; // Expanded key length
	const unsigned char *label = test_tls13_label_ext_binder;
	uint8_t label_len = sizeof(test_tls13_label_ext_binder);
	const unsigned char *context;
	uint8_t context_len;

	if (tls1_3_es_algo == HSM_KEY_DERIVATION_TLS1_3_EARLY_SECRET_SHA256) {
		hash_algo_size = HSM_HASH_ALGO_SHA_256_SIZE;
		context = context_buffer;
		context_len = sizeof(context_buffer);
		psk_bit_key_size = HSM_KEY_SIZE_DERIVE_256;
	} else {
		hash_algo_size = HSM_HASH_ALGO_SHA_384_SIZE;
		context = context_384_buffer;
		context_len = sizeof(context_384_buffer);
		psk_bit_key_size = HSM_KEY_SIZE_DERIVE_384;
	}

	length = hash_algo_size;

	/* 1. Prepare User Fixed Info or HKDF label */
	memset(hkdf_label, 0, sizeof(hkdf_label));

	tls13_hkdf_label_encode(length,
				label, label_len,
				context, context_len,
				hkdf_label, &hkdf_label_len);

	/* 2.1. Prepare Input Plaintext Context, without optional PSK */
	memset(&in_content, 0, sizeof(in_content_tls13_args_t));

	in_content.ver = 0x1;
	in_content.keystore_id = key_store_id;
	in_content.tls1_3_algo = tls1_3_es_algo;
	in_content.priv_key_id = key_id; // Ignored for Early Secrets.
	in_content.psk_id = 0x0; // Optional PSK not used.

	/* 2.2. Case 1.1. Derived Key stored in ELE FW. */
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
#ifdef ELE_DEBUG
	printf("\t--Derived Key ID: 0x%x\n", key_ex_args.out_derived_key_id);
	printf("\t--Salt Size: 0x%x\n", key_ex_args.out_salt_sz);
#endif
	if (err != HSM_NO_ERROR)
		goto out;

	/* Return the Early Secret key_id to support other testings. (KM & IV) */
	*test_key_id = key_ex_args.out_derived_key_id;

	/* 3.1. Generate PSK ID for deriving Early Secret */
	generate_test_key(key_mgmt_hdl,
			  HSM_KEY_TYPE_DERIVE,
			  psk_bit_key_size,
			  HSM_SE_KEY_STORAGE_VOLATILE,
			  HSM_KEY_USAGE_DERIVE,
			  tls1_3_key_permitted_algo,
			  0x0,
			  0x0,
			  40,
			  0x0, NULL,
			  0x0, NULL,
			  &psk_id);

	/* 3.2. Prepare Input Plaintext Context, with PSK ID */
	in_content.psk_id = psk_id;

	/* 3.3. Case 1.2. Derived Key stored in ELE FW. */
	memset(&key_ex_args, 0, sizeof(op_key_exchange_args_t));

	key_ex_args.flags = HSM_OP_KEY_EXCHANGE_FLAGS_INPUT_PLAINTEXT_CONTENT;
	key_ex_args.in_content_sz = sizeof(in_content_tls13_args_t);
	key_ex_args.in_content = (uint8_t *)(&in_content);
	key_ex_args.user_fixed_info_sz = hkdf_label_len;
	key_ex_args.user_fixed_info = (uint8_t *)hkdf_label;

	err = hsm_key_exchange(key_mgmt_hdl, &key_ex_args);
	printf("\nhsm_key_exchange [TLS 1.3 ES case #1.2] err: 0x%x\n", err);
#ifdef ELE_DEBUG
	printf("\t--Derived Key ID: 0x%x\n", key_ex_args.out_derived_key_id);
	printf("\t--Salt Size: 0x%x\n", key_ex_args.out_salt_sz);
#endif
	delete_test_key(key_mgmt_hdl, psk_id, 0);

	if (err != HSM_NO_ERROR)
		goto out;

	delete_test_key(key_mgmt_hdl, key_ex_args.out_derived_key_id, 0);

	/* 4. Case 1.3. Export Derived/Output Key Buffer, without PSK */
	in_content.psk_id = 0x0;
#if SUPPORT_KEY_EXCHANGE_PLAINTEXT_OUTPUT
	memset(&key_ex_args, 0, sizeof(op_key_exchange_args_t));
	memset(output_key_buffer, 0, sizeof(output_key_buffer));

	key_ex_args.flags = HSM_OP_KEY_EXCHANGE_FLAGS_INPUT_PLAINTEXT_CONTENT |
			    HSM_OP_KEY_EXCHANGE_FLAGS_RETURN_OUTPUT;
	key_ex_args.in_content_sz = sizeof(in_content_tls13_args_t);
	key_ex_args.in_content = (uint8_t *)(&in_content);
	key_ex_args.in_pub_buffer_sz = 0x0;
	key_ex_args.in_pub_buffer = NULL;
	key_ex_args.user_fixed_info_sz = hkdf_label_len;
	key_ex_args.user_fixed_info = (uint8_t *)hkdf_label;
	key_ex_args.output_sz = length;
	key_ex_args.output = (uint8_t *)output_key_buffer;

	err = hsm_key_exchange(key_mgmt_hdl, &key_ex_args);
	printf("hsm_key_exchange [TLS 1.3 ES case #1.3] err: 0x%x\n", err);
#ifdef ELE_DEBUG
	printf("\t--Derived Key ID: 0x%x\n", key_ex_args.out_derived_key_id);
	printf("\t--Salt Size: 0x%x\n", key_ex_args.out_salt_sz);
	printf("\n--Derived Key Buffer:\n");
	dump_hex(key_ex_args.output, key_ex_args.output_sz);
#endif
	if (err != HSM_NO_ERROR)
		goto out;
#endif
out:
	return;
}

static uint32_t mbedtls_derive_label_w_handshake_secret(hsm_bit_key_sz_t bit_key_sz,
							hsm_key_type_t key_type,
							uint8_t *peer_pub_key,
							uint32_t peer_pub_key_size,
							uint8_t *priv_key,
							uint32_t priv_key_size,
							uint32_t hash_algo,
							uint32_t hash_algo_size,
							const uint8_t *label,
							uint32_t label_size,
							const uint8_t *context,
							uint32_t context_size,
							uint8_t *derived_secret,
							uint32_t derived_secret_size)
{
	uint32_t ret;
	char mbedtls_shared_secret[HSM_HASH_MAX_SIZE] = {0};
	uint32_t mbedtls_shared_secret_len = sizeof(mbedtls_shared_secret);
	char mbedtls_ikm[HSM_HASH_MAX_SIZE] = {0};
	char mbedtls_early_secret[HSM_HASH_MAX_SIZE] = {0};
	char mbedtls_derived_early_secret[HSM_HASH_MAX_SIZE] = {0};
	char mbedtls_handshake_secret[HSM_HASH_MAX_SIZE] = {0};
	char mbedtls_c_hs_traffic_secret[HSM_HASH_MAX_SIZE] = {0};

	ret = my_mbedtls_ecdh(bit_key_sz, key_type,
			      peer_pub_key, peer_pub_key_size,
			      priv_key, priv_key_size,
			      mbedtls_shared_secret,
			      &mbedtls_shared_secret_len);
	if (ret)
		goto out;

	ret = my_mbedtls_hkdf_extract(hash_algo,
				      NULL, 0,
				      mbedtls_ikm,
				      hash_algo_size,
				      mbedtls_early_secret,
				      hash_algo_size);
	if (ret)
		goto out;

	ret = mbedtls_wapi_tls13_derive_secret(hash_algo,
					       mbedtls_early_secret,
					       hash_algo_size,
					       test_tls13_label_derived,
					       sizeof(test_tls13_label_derived),
					       NULL, 0,
					       TEST_TLS1_3_CTX_UNHASHED,
					       mbedtls_derived_early_secret,
					       hash_algo_size);
	if (ret)
		goto out;

	ret = my_mbedtls_hkdf_extract(hash_algo,
				      mbedtls_derived_early_secret,
				      hash_algo_size,
				      mbedtls_shared_secret,
				      mbedtls_shared_secret_len,
				      mbedtls_handshake_secret,
				      hash_algo_size);
	if (ret)
		goto out;

	/* Derive Secret on the basis of Mbed-TLS handshake secret. */
	ret = mbedtls_wapi_tls13_derive_secret(hash_algo,
					       mbedtls_handshake_secret,
					       hash_algo_size,
					       label, label_size,
					       context, context_size,
					       TEST_TLS1_3_CTX_HASHED,
					       derived_secret,
					       derived_secret_size);
out:

	return ret;
}

static hsm_err_t test_aes_cbc_encrypt(uint32_t key_id,
				      uint8_t *input,
				      uint32_t input_len,
				      uint8_t *iv,
				      uint32_t iv_len,
				      uint8_t *output,
				      uint32_t output_len)
{
	hsm_err_t err;
	op_cipher_one_go_args_t args;

	memset(&args, 0, sizeof(op_cipher_one_go_args_t));

	args.key_identifier = key_id;
	args.iv = iv;
	args.iv_size = iv_len;
	args.cipher_algo = HSM_CIPHER_ONE_GO_ALGO_CBC;
	args.flags = HSM_CIPHER_ONE_GO_FLAGS_ENCRYPT;
	args.input = input;
	args.output = output;
	args.input_size = input_len;
	args.output_size = output_len;

	err = hsm_do_cipher(get_key_store_hdl(), &args);
	if (err)
		printf("hsm_cipher_one_go (encrypt) err: 0x%x\n", err);

	return err;
}

/**
 * RFC 8446 section 7.3. Traffic Key Calculation - TLS 1.3. KM
 *
 *   [sender]_write_key  = HKDF-Expand-Label(Secret, "key", "", key_length)
 *
 *   where Secret can be as follows:
 *     - client_early_traffic_secret,
 *     - [sender]_handshake_traffic_secret
 *     - [sender]_application_traffic_secret_N
 */
static void test_tls1_3_km(hsm_hdl_t key_mgmt_hdl,
			   uint32_t priv_key_id,
			   uint32_t tls1_3_km_algo,
			   uint16_t derived_key_type,
			   uint16_t derived_key_bits_size,
			   uint32_t derived_key_lifetime,
			   uint32_t derived_key_usage,
			   uint32_t derived_key_permitted_algo,
			   uint32_t derived_key_lifecycle,
			   uint8_t *in_secret,
			   uint32_t in_secret_size,
			   uint32_t hash_algo,
			   uint32_t key_store_id)
{
	hsm_err_t err;
	uint32_t ret;
	in_content_tls13_args_t in_content = {0};
	op_key_exchange_args_t key_ex_args = {0};
	/* HKDF label related variables */
	unsigned char hkdf_label[TEST_TLS1_3_HKDF_LABEL_MAX_LEN];
	uint16_t hkdf_label_len = 0;
	uint16_t length = BITS_TO_BYTES(derived_key_bits_size);
	const unsigned char *label = test_tls13_label_key;
	uint8_t label_len = sizeof(test_tls13_label_key);
	uint8_t ciphered_data[32] = {0};
	char mbedtls_km_write_key[16] = {0};
	char mbedtls_ciphered_data[32] = {0};

	/* Prepare Input Plaintext Context for TLS 1.3 KM, without optional PSK */
	memset(&in_content, 0, sizeof(in_content_tls13_args_t));

	in_content.ver = 0x1;
	in_content.keystore_id = key_store_id;
	in_content.tls1_3_algo = tls1_3_km_algo;
	in_content.priv_key_id = priv_key_id;
	in_content.derived_key_type = derived_key_type;
	in_content.derived_key_bits_size = derived_key_bits_size;
	in_content.derived_key_lifetime = derived_key_lifetime;
	in_content.derived_key_usage = derived_key_usage;
	in_content.derived_key_permitted_algo = derived_key_permitted_algo;
	in_content.derived_key_lifecycle = derived_key_lifecycle;

	/* Prepare User Fixed Info or HKDF label */
	memset(hkdf_label, 0, sizeof(hkdf_label));
	tls13_hkdf_label_encode(length,
				label, label_len,
				NULL, 0,
				hkdf_label, &hkdf_label_len);

	/* Derive TLS 1.3 Keying Material - Write Key */
	memset(&key_ex_args, 0, sizeof(op_key_exchange_args_t));

	key_ex_args.flags = HSM_OP_KEY_EXCHANGE_FLAGS_INPUT_PLAINTEXT_CONTENT;
	key_ex_args.in_content_sz = sizeof(in_content_tls13_args_t);
	key_ex_args.in_content = (uint8_t *)(&in_content);
	key_ex_args.user_fixed_info_sz = hkdf_label_len;
	key_ex_args.user_fixed_info = (uint8_t *)hkdf_label;

	err = hsm_key_exchange(key_mgmt_hdl, &key_ex_args);
	printf("\nhsm_key_exchange [TLS 1.3 KM - write key] err: 0x%x\n", err);
	if (err != HSM_NO_ERROR)
		goto out;

	/* AES ENCRYPT operation using generated TLS 1.3 Write Key */
	err = test_aes_cbc_encrypt(key_ex_args.out_derived_key_id,
				   test_msg,
				   sizeof(test_msg),
				   iv,
				   sizeof(iv),
				   ciphered_data,
				   sizeof(ciphered_data));
	if (err != HSM_NO_ERROR)
		goto out;

	/* Mbed-TLS: Derive Keying Material with same params as above. */
	ret = mbedtls_wapi_tls13_derive_secret(hash_algo,
					       in_secret,
					       in_secret_size,
					       test_tls13_label_key,
					       sizeof(test_tls13_label_key),
					       NULL, 0,
					       TEST_TLS1_3_CTX_HASHED,
					       mbedtls_km_write_key,
					       sizeof(mbedtls_km_write_key));
	if (ret)
		goto out;

	/* Mbed-TLS: Cipher operation */
	ret = my_mbedtls_aes_cbc(derived_key_bits_size,
				 mbedtls_km_write_key,
				 HSM_CIPHER_ONE_GO_FLAGS_ENCRYPT,
				 test_msg,
				 sizeof(test_msg),
				 mbedtls_ciphered_data,
				 iv);
	if (ret)
		goto out;

	/* Compare Encrypted Data generated using TLS 1.3 KM, by ELE FW and Mbed-TLS. */
	if (!memcmp(mbedtls_ciphered_data, ciphered_data, sizeof(ciphered_data)))
		printf("\nTLS 1.3: KM: Mbed-TLS validation. SUCCESS\n");
	else
		printf("\nTLS 1.3: KM: Mbed-TLS validation. FAILED\n");
out:
	return;
}

/**
 * RFC 8446 section 7.3. Traffic Key Calculation - TLS 1.3. IV
 *
 *   [sender]_write_iv  = HKDF-Expand-Label(Secret, "iv", "", iv_length)
 *
 *   where Secret can be as follows:
 *     - client_early_traffic_secret,
 *     - [sender]_handshake_traffic_secret
 *     - [sender]_application_traffic_secret_N
 */
static void test_tls1_3_iv(hsm_hdl_t key_mgmt_hdl,
			   uint32_t priv_key_id,
			   uint32_t tls1_3_iv_algo,
			   uint16_t iv_len,
			   uint8_t *in_secret,
			   uint32_t in_secret_size,
			   uint32_t hash_algo)
{
	hsm_err_t err;
	in_content_tls13_args_t in_content = {0};
	op_key_exchange_args_t key_ex_args = {0};
	char mbedtls_iv[12] = {0};
	uint8_t iv[12] = {0};
	uint32_t ret;
	/* HKDF label related variables */
	unsigned char hkdf_label[TEST_TLS1_3_HKDF_LABEL_MAX_LEN];
	uint16_t hkdf_label_len = 0;
	uint16_t length = iv_len; //IV length
	const unsigned char *label = test_tls13_label_iv;
	uint8_t label_len = sizeof(test_tls13_label_iv);

	/* Prepare Input Plaintext Context for TLS 1.3 IV, without optional PSK */
	memset(&in_content, 0, sizeof(in_content_tls13_args_t));

	in_content.ver = 0x1;
	in_content.tls1_3_algo = tls1_3_iv_algo;
	in_content.priv_key_id = priv_key_id;

	/* Prepare User Fixed Info or HKDF label */
	memset(hkdf_label, 0, sizeof(hkdf_label));
	tls13_hkdf_label_encode(length,
				label, label_len,
				NULL, 0,
				hkdf_label, &hkdf_label_len);

	/* Export Derived TLS 1.3 IV output buffer */
	memset(&key_ex_args, 0, sizeof(op_key_exchange_args_t));

	key_ex_args.flags = HSM_OP_KEY_EXCHANGE_FLAGS_INPUT_PLAINTEXT_CONTENT;
	key_ex_args.in_content_sz = sizeof(in_content_tls13_args_t);
	key_ex_args.in_content = (uint8_t *)(&in_content);
	key_ex_args.user_fixed_info_sz = hkdf_label_len;
	key_ex_args.user_fixed_info = (uint8_t *)hkdf_label;
	key_ex_args.output_sz = iv_len;
	key_ex_args.output = iv;

	err = hsm_key_exchange(key_mgmt_hdl, &key_ex_args);
	printf("\nhsm_key_exchange [TLS 1.3 IV] err: 0x%x\n", err);

	if (err != HSM_NO_ERROR)
		goto out;

	/* Mbed-TLS: Derive TLS 1.3 IV using same params as above */
	ret = mbedtls_wapi_tls13_derive_secret(hash_algo,
					       in_secret,
					       in_secret_size,
					       test_tls13_label_iv,
					       sizeof(test_tls13_label_iv),
					       NULL, 0,
					       TEST_TLS1_3_CTX_HASHED,
					       mbedtls_iv,
					       iv_len);
	if (ret)
		goto out;

	/* Compare the TLS 1.3 IV buffer generated by ELE FW and Mbed-TLS */
	if (!memcmp(mbedtls_iv, iv, iv_len))
		printf("\nTLS 1.3: IV: Mbed-TLS validation. SUCCESS\n");
	else
		printf("\nTLS 1.3: IV: Mbed-TLS validation. FAILED\n");
out:
	return;
}

static uint8_t get_test_ecc_key_pairs(hsm_key_type_t key_type,
				      hsm_bit_key_sz_t bit_key_sz,
				      uint8_t **pub_key,
				      uint32_t *pub_key_size,
				      uint8_t **priv_key,
				      uint32_t *priv_key_size)
{
	if (!pub_key || !pub_key_size || !priv_key || !priv_key_size)
		return FAILURE;

	if (key_type == HSM_KEY_TYPE_ECC_NIST &&
	    bit_key_sz == HSM_KEY_SIZE_ECC_NIST_256) {
		*pub_key = ecc_256_pub_key;
		*pub_key_size = sizeof(ecc_256_pub_key);
		*priv_key = ecc_256_priv_key;
		*priv_key_size = sizeof(ecc_256_priv_key);
	} else if (key_type == HSM_KEY_TYPE_ECC_NIST &&
		   bit_key_sz == HSM_KEY_SIZE_ECC_NIST_384) {
		*pub_key = ecc_384_pub_key;
		*pub_key_size = sizeof(ecc_384_pub_key);
		*priv_key = ecc_384_priv_key;
		*priv_key_size = sizeof(ecc_384_priv_key);
	} else if (key_type == HSM_KEY_TYPE_ECC_MONTGOMERY &&
		   bit_key_sz == HSM_KEY_SIZE_ECC_MONTGOMERY_255) {
		*pub_key = ecc_x25519_pub_key;
		*pub_key_size = sizeof(ecc_x25519_pub_key);
		*priv_key = ecc_x25519_priv_key;
		*priv_key_size = sizeof(ecc_x25519_priv_key);
	} else if (key_type == HSM_KEY_TYPE_ECC_MONTGOMERY &&
		   bit_key_sz == HSM_KEY_SIZE_ECC_MONTGOMERY_448) {
		*pub_key = ecc_x448_pub_key;
		*pub_key_size = sizeof(ecc_x448_pub_key);
		*priv_key = ecc_x448_priv_key;
		*priv_key_size = sizeof(ecc_x448_priv_key);
	} else {
		return FAILURE;
	}

	return SUCCESS;
}

/**
 * RFC 8446 section 7.1 Part-2 Handshake Secrets
 *
 *      Derive-Secret(., "derived", "")    //From Early Secrets stage
 *            |
 *            v
 *    (EC)DHE -> HKDF-Extract = Handshake Secret
 *            |
 *            +-----> Derive-Secret(., "c hs traffic",
 *            |                     ClientHello...ServerHello)
 *            |                     = client_handshake_traffic_secret
 *            |
 *            +-----> Derive-Secret(., "s hs traffic",
 *            |                     ClientHello...ServerHello)
 *            |                     = server_handshake_traffic_secret
 *            v
 *      Derive-Secret(., "derived", "")
 *            |
 *            v
 */
static void test_tls1_3_handshake_secrets(hsm_hdl_t key_mgmt_hdl,
					  hsm_key_type_t key_type,
					  hsm_bit_key_sz_t bit_key_sz,
					  uint32_t tls1_3_key_permitted_algo,
					  uint32_t tls1_3_hs_algo,
					  uint32_t *test_key_id,
					  uint8_t *mbedtls_secret,
					  uint32_t *mbedtls_secret_size,
					  uint32_t key_store_id)
{
	hsm_err_t err;
	int ret;
	in_content_tls13_args_t in_content = {0};
	op_key_exchange_args_t key_ex_args = {0};
	op_generate_key_args_t key_gen_args = {0};
	op_delete_key_args_t del_args = {0};
	uint32_t key_id = 0; //Private Key ID, ELE FW
	uint32_t output_key_buffer[TEST_TLS1_3_DERIVED_MAX_KEY_SIZE];
	uint8_t fw_pub_key[96] = {0};
	char mbedtls_c_hs_traffic_secret[HSM_HASH_MAX_SIZE] = {0};
	uint8_t *peer_pub_key = NULL;
	uint32_t pub_key_size = 0;
	uint8_t *peer_priv_key = NULL;
	uint32_t priv_key_size = 0;
	uint32_t hash_algo;
	uint32_t hash_algo_size;
	uint32_t psk_id = 0;
	uint32_t psk_bit_key_size;

	/**************Handshake Secrets - Client HS traffic ***************/

	/* HKDF label related variables */
	unsigned char hkdf_label[TEST_TLS1_3_HKDF_LABEL_MAX_LEN];
	uint16_t hkdf_label_len = 0;
	uint16_t length; // Expanded key length
	const unsigned char *label = test_tls13_label_client_handshake_traffic;
	uint8_t label_len = sizeof(test_tls13_label_client_handshake_traffic);
	const unsigned char *context;
	uint8_t context_len;

	if (tls1_3_hs_algo == HSM_KEY_DERIVATION_TLS1_3_HANDSHAKE_SECRET_SHA256) {
		hash_algo = HSM_HASH_ALGO_SHA_256;
		hash_algo_size = HSM_HASH_ALGO_SHA_256_SIZE;
		context = context_buffer;
		context_len = sizeof(context_buffer);
		psk_bit_key_size = HSM_KEY_SIZE_DERIVE_256;
	} else {
		hash_algo = HSM_HASH_ALGO_SHA_384;
		hash_algo_size = HSM_HASH_ALGO_SHA_384_SIZE;
		context = context_384_buffer;
		context_len = sizeof(context_384_buffer);
		psk_bit_key_size = HSM_KEY_SIZE_DERIVE_384;
	}

	length = hash_algo_size;

	ret = get_test_ecc_key_pairs(key_type, bit_key_sz,
				     &peer_pub_key, &pub_key_size,
				     &peer_priv_key, &priv_key_size);
	if (ret) {
		printf("\nFailed to get test ECC key pairs.\n");
		goto out;
	}

	/* 1. Generate ELE Private Key for Key Agreement process */
	key_gen_args.key_identifier = &key_id;
	key_gen_args.key_group = 40;
	key_gen_args.key_lifetime = HSM_SE_KEY_STORAGE_VOLATILE;
	key_gen_args.key_usage = HSM_KEY_USAGE_DERIVE;
	key_gen_args.permitted_algo = tls1_3_key_permitted_algo;
	key_gen_args.flags = 0x0;
	key_gen_args.key_type = key_type;
	key_gen_args.bit_key_sz = bit_key_sz;
	key_gen_args.key_lifecycle = 0x0; // Current Device Lifecycle
	key_gen_args.out_key = fw_pub_key;
	key_gen_args.out_size = pub_key_size;

	err = hsm_generate_key(key_mgmt_hdl, &key_gen_args);
	if (err != HSM_NO_ERROR)
		printf("\nhsm_generate_key (KeyPair) err: 0x%x\n", err);

	/* 2. Prepare User Fixed Info or HKDF label */
	memset(hkdf_label, 0, sizeof(hkdf_label));
	tls13_hkdf_label_encode(length,
				label, label_len,
				context, context_len,
				hkdf_label, &hkdf_label_len);

	/* 3. Prepare Input Plaintext Context for TLS 1.3, without optional PSK */
	memset(&in_content, 0, sizeof(in_content_tls13_args_t));

	in_content.ver = 0x1;
	in_content.keystore_id = key_store_id;
	in_content.tls1_3_algo = tls1_3_hs_algo;
	in_content.priv_key_id = key_id;

	/* 4. Case 1.1. Derived Key stored in ELE FW. */
	memset(&key_ex_args, 0, sizeof(op_key_exchange_args_t));

	key_ex_args.flags = HSM_OP_KEY_EXCHANGE_FLAGS_INPUT_PLAINTEXT_CONTENT;
	key_ex_args.in_content_sz = sizeof(in_content_tls13_args_t);
	key_ex_args.in_content = (uint8_t *)(&in_content);
	key_ex_args.in_pub_buffer_sz = pub_key_size;
	key_ex_args.in_pub_buffer = peer_pub_key;
	key_ex_args.user_fixed_info_sz = hkdf_label_len;
	key_ex_args.user_fixed_info = (uint8_t *)hkdf_label;
	key_ex_args.output_sz = 0;
	key_ex_args.output = NULL;

	err = hsm_key_exchange(key_mgmt_hdl, &key_ex_args);
	printf("\nhsm_key_exchange [TLS 1.3 HS case  #1.1] err: 0x%x\n", err);
#ifdef ELE_DEBUG
	printf("\t--Derived Key ID: 0x%x\n", key_ex_args.out_derived_key_id);
	printf("\t--Salt Size: 0x%x\n", key_ex_args.out_salt_sz);
#endif
	if (err != HSM_NO_ERROR)
		goto out;

	/* Return the Handshake Secret key_id to support other testings. (KM & IV) */
	*test_key_id = key_ex_args.out_derived_key_id;

	/* 5.1. Generate PSK ID for deriving Handshake Secret */
	generate_test_key(key_mgmt_hdl,
			  HSM_KEY_TYPE_DERIVE,
			  psk_bit_key_size,
			  HSM_SE_KEY_STORAGE_VOLATILE,
			  HSM_KEY_USAGE_DERIVE,
			  tls1_3_key_permitted_algo,
			  0x0,
			  0x0,
			  40,
			  0x0, NULL,
			  0x0, NULL,
			  &psk_id);

	/* 5.2. Prepare Input Plaintext Context for TLS 1.3, with PSK ID */
	in_content.psk_id = psk_id;

	/* 5.3. Case 1.2. Derived Key stored in ELE FW. */
	memset(&key_ex_args, 0, sizeof(op_key_exchange_args_t));

	key_ex_args.flags = HSM_OP_KEY_EXCHANGE_FLAGS_INPUT_PLAINTEXT_CONTENT;
	key_ex_args.in_content_sz = sizeof(in_content_tls13_args_t);
	key_ex_args.in_content = (uint8_t *)(&in_content);
	key_ex_args.in_pub_buffer_sz = pub_key_size;
	key_ex_args.in_pub_buffer = peer_pub_key;
	key_ex_args.user_fixed_info_sz = hkdf_label_len;
	key_ex_args.user_fixed_info = (uint8_t *)hkdf_label;
	key_ex_args.output_sz = 0;
	key_ex_args.output = NULL;

	err = hsm_key_exchange(key_mgmt_hdl, &key_ex_args);
	printf("\nhsm_key_exchange [TLS 1.3 HS case  #1.2] err: 0x%x\n", err);
#ifdef ELE_DEBUG
	printf("\t--Derived Key ID: 0x%x\n", key_ex_args.out_derived_key_id);
	printf("\t--Salt Size: 0x%x\n", key_ex_args.out_salt_sz);
#endif
	delete_test_key(key_mgmt_hdl, psk_id, 0);

	if (err != HSM_NO_ERROR)
		goto out;

	delete_test_key(key_mgmt_hdl, key_ex_args.out_derived_key_id, 0);

	/* 6. Case 1.3. Export Derived/Output Key Buffer, without PSK */
	in_content.psk_id = 0x0;
#if SUPPORT_KEY_EXCHANGE_PLAINTEXT_OUTPUT
	memset(&key_ex_args, 0, sizeof(op_key_exchange_args_t));
	memset(output_key_buffer, 0, sizeof(output_key_buffer));

	key_ex_args.flags = HSM_OP_KEY_EXCHANGE_FLAGS_INPUT_PLAINTEXT_CONTENT |
			    HSM_OP_KEY_EXCHANGE_FLAGS_RETURN_OUTPUT;
	key_ex_args.in_content_sz = sizeof(in_content_tls13_args_t);
	key_ex_args.in_content = (uint8_t *)(&in_content);
	key_ex_args.in_pub_buffer_sz = pub_key_size;
	key_ex_args.in_pub_buffer = peer_pub_key;
	key_ex_args.user_fixed_info_sz = hkdf_label_len;
	key_ex_args.user_fixed_info = (uint8_t *)hkdf_label;
	key_ex_args.output_sz = length;
	key_ex_args.output = (uint8_t *)output_key_buffer;

	err = hsm_key_exchange(key_mgmt_hdl, &key_ex_args);
	printf("hsm_key_exchange [TLS 1.3 HS case #1.3] err: 0x%x\n", err);
#ifdef ELE_DEBUG
	printf("\t--Derived Key ID: 0x%x\n", key_ex_args.out_derived_key_id);
	printf("\t--Salt Size: 0x%x\n", key_ex_args.out_salt_sz);
	printf("\n--Derived Key Buffer:\n");
	dump_hex(key_ex_args.output, key_ex_args.output_sz);
#endif
	/**
	 * 6. Mbed-TLS validation for the generated Handshake secret.
	 *    Currently done for only ECC NIST key type.
	 */
	if (key_type != HSM_KEY_TYPE_ECC_NIST)
		goto out;

	/* Mbed-TLS: Get TLS 1.3 Handshake secret (label "c hs traffic") in plain */
	ret = mbedtls_derive_label_w_handshake_secret(bit_key_sz,
						      key_type,
						      fw_pub_key,
						      pub_key_size,
						      peer_priv_key,
						      priv_key_size,
						      hash_algo,
						      hash_algo_size,
						      label,
						      label_len,
						      context,
						      context_len,
						      mbedtls_c_hs_traffic_secret,
						      hash_algo_size);
	if (ret)
		goto out;

	/* Return the Mbed-TLS Handshake secret */
	memcpy(mbedtls_secret, mbedtls_c_hs_traffic_secret, hash_algo_size);
	*mbedtls_secret_size = hash_algo_size;

	if (err != HSM_NO_ERROR)
		goto out;

	if (!memcmp(key_ex_args.output,
		    mbedtls_c_hs_traffic_secret,
		    key_ex_args.output_sz))
		printf("\nTLS 1.3: HS: Mbed-TLS validation. SUCCESS\n");
	else
		printf("\nTLS 1.3: HS: Mbed-TLS validation. FAILED\n");
#endif
out:
	/* 7. Delete the Generated test Key */
	if (key_id)
		delete_test_key(key_mgmt_hdl, key_id, 0);

	return;
}

/**
 * RFC 8446 section 7.1 Part-3 Master Secrets
 *
 *      Derive-Secret(., "derived", "")    //From Handshake Secrets stage
 *            |
 *            v
 *     0 -> HKDF-Extract = Master Secret
 *            |
 *            +-----> Derive-Secret(., "c ap traffic",
 *            |                     ClientHello...server Finished)
 *            |                     = client_application_traffic_secret_0
 *            |
 *            +-----> Derive-Secret(., "s ap traffic",
 *            |                     ClientHello...server Finished)
 *            |                     = server_application_traffic_secret_0
 *            |
 *            +-----> Derive-Secret(., "exp master",
 *            |                     ClientHello...server Finished)
 *            |                     = exporter_master_secret
 *            |
 *            +-----> Derive-Secret(., "res master",
 *                                  ClientHello...client Finished)
 *                                  = resumption_master_secret
 */
static void test_tls1_3_master_secrets(hsm_hdl_t key_mgmt_hdl,
				       hsm_key_type_t key_type,
				       hsm_bit_key_sz_t bit_key_sz,
				       uint32_t tls1_3_key_permitted_algo,
				       uint32_t tls1_3_ms_algo,
				       uint32_t *test_key_id,
				       uint32_t key_store_id)
{
	hsm_err_t err;
	int ret;
	in_content_tls13_args_t in_content = {0};
	op_key_exchange_args_t key_ex_args = {0};
	op_generate_key_args_t key_gen_args = {0};
	op_delete_key_args_t del_args = {0};
	uint32_t key_id = 0; //Private Key ID, ELE FW
	uint32_t output_key_buffer[TEST_TLS1_3_DERIVED_MAX_KEY_SIZE];
	uint8_t *peer_pub_key = NULL;
	uint32_t pub_key_size = 0;
	uint8_t *peer_priv_key = NULL;
	uint32_t priv_key_size = 0;
	uint32_t hash_algo;
	uint32_t hash_algo_size;
	uint32_t psk_id = 0;
	uint32_t psk_bit_key_size;

	/**************Master Secrets - Client application traffic ***************/

	/* HKDF label related variables */
	unsigned char hkdf_label[TEST_TLS1_3_HKDF_LABEL_MAX_LEN];
	uint16_t hkdf_label_len = 0;
	uint16_t length; // Expanded key length
	const unsigned char *label = test_tls13_label_client_application_traffic;
	uint8_t label_len = sizeof(test_tls13_label_client_application_traffic);
	const unsigned char *context;
	uint8_t context_len;

	if (tls1_3_ms_algo == HSM_KEY_DERIVATION_TLS1_3_MASTER_SECRET_SHA256) {
		hash_algo = HSM_HASH_ALGO_SHA_256;
		hash_algo_size = HSM_HASH_ALGO_SHA_256_SIZE;
		context = context_buffer;
		context_len = sizeof(context_buffer);
		psk_bit_key_size = HSM_KEY_SIZE_DERIVE_256;
	} else {
		hash_algo = HSM_HASH_ALGO_SHA_384;
		hash_algo_size = HSM_HASH_ALGO_SHA_384_SIZE;
		context = context_384_buffer;
		context_len = sizeof(context_384_buffer);
		psk_bit_key_size = HSM_KEY_SIZE_DERIVE_384;
	}

	length = hash_algo_size;

	ret = get_test_ecc_key_pairs(key_type, bit_key_sz,
				     &peer_pub_key, &pub_key_size,
				     &peer_priv_key, &priv_key_size);
	if (ret) {
		printf("\nFailed to get test ECC key pairs.\n");
		goto out;
	}

	/* 1. Generate ELE Private Key for Key Agreement process */
	key_gen_args.key_identifier = &key_id;
	key_gen_args.key_group = 40;
	key_gen_args.key_lifetime = HSM_SE_KEY_STORAGE_VOLATILE;
	key_gen_args.key_usage = HSM_KEY_USAGE_DERIVE;
	key_gen_args.permitted_algo = tls1_3_key_permitted_algo;
	key_gen_args.flags = 0x0;
	key_gen_args.key_type = key_type;
	key_gen_args.bit_key_sz = bit_key_sz;
	key_gen_args.key_lifecycle = 0x0; // Current Device Lifecycle
	key_gen_args.out_key = NULL;
	key_gen_args.out_size = 0x0;

	err = hsm_generate_key(key_mgmt_hdl, &key_gen_args);
	if (err != HSM_NO_ERROR)
		printf("\nhsm_generate_key (KeyPair) err: 0x%x\n", err);

	/* 2. Prepare User Fixed Info or HKDF label */
	memset(hkdf_label, 0, sizeof(hkdf_label));
	tls13_hkdf_label_encode(length,
				label, label_len,
				context, context_len,
				hkdf_label, &hkdf_label_len);

	/* 3.1. Prepare Input Plaintext Context for TLS 1.3, without optional PSK */
	memset(&in_content, 0, sizeof(in_content_tls13_args_t));

	in_content.ver = 0x1;
	in_content.keystore_id = key_store_id;
	in_content.tls1_3_algo = tls1_3_ms_algo;
	in_content.priv_key_id = key_id;
	in_content.psk_id = 0x0; // Optional PSK not used.

	/* 3.2. Case 1.1. Derived Key stored in ELE FW. */
	memset(&key_ex_args, 0, sizeof(op_key_exchange_args_t));

	key_ex_args.flags = HSM_OP_KEY_EXCHANGE_FLAGS_INPUT_PLAINTEXT_CONTENT;
	key_ex_args.in_content_sz = sizeof(in_content_tls13_args_t);
	key_ex_args.in_content = (uint8_t *)(&in_content);
	key_ex_args.in_pub_buffer_sz = pub_key_size;
	key_ex_args.in_pub_buffer = peer_pub_key;
	key_ex_args.user_fixed_info_sz = hkdf_label_len;
	key_ex_args.user_fixed_info = (uint8_t *)hkdf_label;
	key_ex_args.output_sz = 0;
	key_ex_args.output = NULL;

	err = hsm_key_exchange(key_mgmt_hdl, &key_ex_args);
	printf("\nhsm_key_exchange [TLS 1.3 MS case #1.1] err: 0x%x\n", err);
#ifdef ELE_DEBUG
	printf("\t--Derived Key ID: 0x%x\n", key_ex_args.out_derived_key_id);
	printf("\t--Salt Size: 0x%x\n", key_ex_args.out_salt_sz);
#endif
	if (err != HSM_NO_ERROR)
		goto out;

	/* Return the Master Secret key_id to support other testings. (KM & IV) */
	*test_key_id = key_ex_args.out_derived_key_id;

	/* 4.1. Generate PSK ID for deriving Master Secret */
	generate_test_key(key_mgmt_hdl,
			  HSM_KEY_TYPE_DERIVE,
			  psk_bit_key_size,
			  HSM_SE_KEY_STORAGE_VOLATILE,
			  HSM_KEY_USAGE_DERIVE,
			  tls1_3_key_permitted_algo,
			  0x0,
			  0x0,
			  40,
			  0x0, NULL,
			  0x0, NULL,
			  &psk_id);

	/* 4.2. Prepare Input Plaintext Context for TLS 1.3, with PSK ID */
	in_content.psk_id = psk_id;

	/* 4.3. Case 1.2. Derived Key stored in ELE FW. */
	memset(&key_ex_args, 0, sizeof(op_key_exchange_args_t));

	key_ex_args.flags = HSM_OP_KEY_EXCHANGE_FLAGS_INPUT_PLAINTEXT_CONTENT;
	key_ex_args.in_content_sz = sizeof(in_content_tls13_args_t);
	key_ex_args.in_content = (uint8_t *)(&in_content);
	key_ex_args.in_pub_buffer_sz = pub_key_size;
	key_ex_args.in_pub_buffer = peer_pub_key;
	key_ex_args.user_fixed_info_sz = hkdf_label_len;
	key_ex_args.user_fixed_info = (uint8_t *)hkdf_label;
	key_ex_args.output_sz = 0;
	key_ex_args.output = NULL;

	err = hsm_key_exchange(key_mgmt_hdl, &key_ex_args);
	printf("\nhsm_key_exchange [TLS 1.3 MS case #1.2] err: 0x%x\n", err);
#ifdef ELE_DEBUG
	printf("\t--Derived Key ID: 0x%x\n", key_ex_args.out_derived_key_id);
	printf("\t--Salt Size: 0x%x\n", key_ex_args.out_salt_sz);
#endif
	delete_test_key(key_mgmt_hdl, psk_id, 0);

	if (err != HSM_NO_ERROR)
		goto out;

	delete_test_key(key_mgmt_hdl, key_ex_args.out_derived_key_id, 0);

	/* 5. Case 1.3. Export Derived/Output Key Buffer, without PSK */
	in_content.psk_id = 0x0;
#if SUPPORT_KEY_EXCHANGE_PLAINTEXT_OUTPUT
	memset(&key_ex_args, 0, sizeof(op_key_exchange_args_t));
	memset(output_key_buffer, 0, sizeof(output_key_buffer));

	key_ex_args.flags = HSM_OP_KEY_EXCHANGE_FLAGS_INPUT_PLAINTEXT_CONTENT |
			    HSM_OP_KEY_EXCHANGE_FLAGS_RETURN_OUTPUT;
	key_ex_args.in_content_sz = sizeof(in_content_tls13_args_t);
	key_ex_args.in_content = (uint8_t *)(&in_content);
	key_ex_args.in_pub_buffer_sz = pub_key_size;
	key_ex_args.in_pub_buffer = peer_pub_key;
	key_ex_args.user_fixed_info_sz = hkdf_label_len;
	key_ex_args.user_fixed_info = (uint8_t *)hkdf_label;
	key_ex_args.output_sz = length;
	key_ex_args.output = (uint8_t *)output_key_buffer;

	err = hsm_key_exchange(key_mgmt_hdl, &key_ex_args);
	printf("hsm_key_exchange [TLS 1.3 MS case #1.3] err: 0x%x\n", err);
#ifdef ELE_DEBUG
	printf("\t--Derived Key ID: 0x%x\n", key_ex_args.out_derived_key_id);
	printf("\t--Salt Size: 0x%x\n", key_ex_args.out_salt_sz);
	printf("\n--Derived Key Buffer:\n");
	dump_hex(key_ex_args.output, key_ex_args.output_sz);
#endif
#endif
out:
	/* 6. Delete the Generated test Key */
	if (key_id)
		delete_test_key(key_mgmt_hdl, key_id, 0);

	return;
}

/**
 * TLS 1.3 tests for:
 *	- "Early Secrets",
 *	- "Handshake Secrets",
 *	- "Master Secrets"
 */
void key_exchange_test_tls1_3(hsm_hdl_t key_mgmt_hdl, uint32_t key_store_id)
{
	uint32_t test_key_id = 0;
	uint32_t mbedtls_secret_size = 0;
	uint8_t mbedtls_secret[HSM_HASH_MAX_SIZE] = {0};

	printf("\n-----------------------------------------------------\n");
	printf("Key Exchange API tests - TLS 1.3");
	printf("\n-----------------------------------------------------\n");

	printf("\nECC_NIST & HSM_KEY_DERIVATION_TLS1_3_EARLY_SECRET_SHA256:\n");
	printf("---------------------------------------------------------\n");
	test_tls1_3_early_secrets(key_mgmt_hdl,
				  PERMITTED_ALGO_TLS1_3_MASTER_SECRET_SHA256,
				  HSM_KEY_DERIVATION_TLS1_3_EARLY_SECRET_SHA256,
				  &test_key_id,
				  key_store_id);

	delete_test_key(key_mgmt_hdl, test_key_id, 0);

	printf("\nECC_NIST & HSM_KEY_DERIVATION_TLS1_3_EARLY_SECRET_SHA384:\n");
	printf("---------------------------------------------------------\n");
	test_tls1_3_early_secrets(key_mgmt_hdl,
				  PERMITTED_ALGO_TLS1_3_MASTER_SECRET_SHA384,
				  HSM_KEY_DERIVATION_TLS1_3_EARLY_SECRET_SHA384,
				  &test_key_id,
				  key_store_id);

	delete_test_key(key_mgmt_hdl, test_key_id, 0);

	printf("\nECC_NIST & HSM_KEY_DERIVATION_TLS1_3_HANDSHAKE_SECRET_SHA256:\n");
	printf("-------------------------------------------------------------\n");
	test_tls1_3_handshake_secrets(key_mgmt_hdl,
				      HSM_KEY_TYPE_ECC_NIST,
				      HSM_KEY_SIZE_ECC_NIST_256,
				      PERMITTED_ALGO_TLS1_3_MASTER_SECRET_SHA256,
				      HSM_KEY_DERIVATION_TLS1_3_HANDSHAKE_SECRET_SHA256,
				      &test_key_id,
				      mbedtls_secret,
				      &mbedtls_secret_size,
				      key_store_id);

	printf("\nECC NIST & HSM_KEY_DERIVATION_TLS1_3_KEYING_MATERIAL_SHA256:\n");
	printf("-------------------------------------------------------------\n");
	test_tls1_3_km(key_mgmt_hdl,
		       test_key_id,
		       HSM_KEY_DERIVATION_TLS1_3_KEYING_MATERIAL_SHA256,
		       HSM_KEY_TYPE_AES,
		       HSM_KEY_SIZE_AES_128,
		       HSM_SE_KEY_STORAGE_VOLATILE,
		       HSM_KEY_USAGE_ENCRYPT | HSM_KEY_USAGE_DECRYPT,
		       PERMITTED_ALGO_CBC_NO_PADDING,
		       0,
		       mbedtls_secret,
		       mbedtls_secret_size,
		       HSM_HASH_ALGO_SHA_256,
		       key_store_id);

	printf("\nECC NIST & HSM_KEY_DERIVATION_TLS1_3_IV_SHA256:\n");
	printf("-------------------------------------------------------------\n");
	test_tls1_3_iv(key_mgmt_hdl,
		       test_key_id,
		       HSM_KEY_DERIVATION_TLS1_3_IV_SHA256,
		       12,
		       mbedtls_secret,
		       mbedtls_secret_size,
		       HSM_HASH_ALGO_SHA_256);

	delete_test_key(key_mgmt_hdl, test_key_id, 0);

	printf("\nECC_NIST & HSM_KEY_DERIVATION_TLS1_3_HANDSHAKE_SECRET_SHA384:\n");
	printf("-------------------------------------------------------------\n");
	test_tls1_3_handshake_secrets(key_mgmt_hdl,
				      HSM_KEY_TYPE_ECC_NIST,
				      HSM_KEY_SIZE_ECC_NIST_384,
				      PERMITTED_ALGO_TLS1_3_MASTER_SECRET_SHA384,
				      HSM_KEY_DERIVATION_TLS1_3_HANDSHAKE_SECRET_SHA384,
				      &test_key_id,
				      mbedtls_secret,
				      &mbedtls_secret_size,
				      key_store_id);

	printf("\nECC NIST & HSM_KEY_DERIVATION_TLS1_3_KEYING_MATERIAL_SHA384:\n");
	printf("-------------------------------------------------------------\n");
	test_tls1_3_km(key_mgmt_hdl,
		       test_key_id,
		       HSM_KEY_DERIVATION_TLS1_3_KEYING_MATERIAL_SHA384,
		       HSM_KEY_TYPE_AES,
		       HSM_KEY_SIZE_AES_128,
		       HSM_SE_KEY_STORAGE_VOLATILE,
		       HSM_KEY_USAGE_ENCRYPT | HSM_KEY_USAGE_DECRYPT,
		       PERMITTED_ALGO_CBC_NO_PADDING,
		       0,
		       mbedtls_secret,
		       mbedtls_secret_size,
		       HSM_HASH_ALGO_SHA_384,
		       key_store_id);

	printf("\nECC NIST & HSM_KEY_DERIVATION_TLS1_3_IV_SHA384:\n");
	printf("-------------------------------------------------------------\n");
	test_tls1_3_iv(key_mgmt_hdl,
		       test_key_id,
		       HSM_KEY_DERIVATION_TLS1_3_IV_SHA384,
		       12,
		       mbedtls_secret,
		       mbedtls_secret_size,
		       HSM_HASH_ALGO_SHA_384);

	delete_test_key(key_mgmt_hdl, test_key_id, 0);

	printf("\nECC_MONTGOMERY (255) & HSM KEY DERIVATION TLS 1.3 HS SHA256:\n");
	printf("-------------------------------------------------------------\n");
	test_tls1_3_handshake_secrets(key_mgmt_hdl,
				      HSM_KEY_TYPE_ECC_MONTGOMERY,
				      HSM_KEY_SIZE_ECC_MONTGOMERY_255,
				      PERMITTED_ALGO_TLS1_3_MASTER_SECRET_SHA256,
				      HSM_KEY_DERIVATION_TLS1_3_HANDSHAKE_SECRET_SHA256,
				      &test_key_id,
				      mbedtls_secret,
				      &mbedtls_secret_size,
				      key_store_id);

	delete_test_key(key_mgmt_hdl, test_key_id, 0);

	printf("\nECC_MONTGOMERY (255) & HSM KEY DERIVATION TLS 1.3 HS SHA384:\n");
	printf("-------------------------------------------------------------\n");
	test_tls1_3_handshake_secrets(key_mgmt_hdl,
				      HSM_KEY_TYPE_ECC_MONTGOMERY,
				      HSM_KEY_SIZE_ECC_MONTGOMERY_255,
				      PERMITTED_ALGO_TLS1_3_MASTER_SECRET_SHA384,
				      HSM_KEY_DERIVATION_TLS1_3_HANDSHAKE_SECRET_SHA384,
				      &test_key_id,
				      mbedtls_secret,
				      &mbedtls_secret_size,
				      key_store_id);

	delete_test_key(key_mgmt_hdl, test_key_id, 0);

	printf("\nECC_MONTGOMERY (448) & HSM KEY DERIVATION TLS 1.3 HS SHA256:\n");
	printf("-------------------------------------------------------------\n");
	test_tls1_3_handshake_secrets(key_mgmt_hdl,
				      HSM_KEY_TYPE_ECC_MONTGOMERY,
				      HSM_KEY_SIZE_ECC_MONTGOMERY_448,
				      PERMITTED_ALGO_TLS1_3_MASTER_SECRET_SHA256,
				      HSM_KEY_DERIVATION_TLS1_3_HANDSHAKE_SECRET_SHA256,
				      &test_key_id,
				      mbedtls_secret,
				      &mbedtls_secret_size,
				      key_store_id);

	delete_test_key(key_mgmt_hdl, test_key_id, 0);

	printf("\nECC_MONTGOMERY (448) & HSM KEY DERIVATION TLS 1.3 HS SHA384:\n");
	printf("-------------------------------------------------------------\n");
	test_tls1_3_handshake_secrets(key_mgmt_hdl,
				      HSM_KEY_TYPE_ECC_MONTGOMERY,
				      HSM_KEY_SIZE_ECC_MONTGOMERY_448,
				      PERMITTED_ALGO_TLS1_3_MASTER_SECRET_SHA384,
				      HSM_KEY_DERIVATION_TLS1_3_HANDSHAKE_SECRET_SHA384,
				      &test_key_id,
				      mbedtls_secret,
				      &mbedtls_secret_size,
				      key_store_id);

	delete_test_key(key_mgmt_hdl, test_key_id, 0);

	printf("\nECC_NIST & HSM_KEY_DERIVATION_TLS1_3_MASTER_SECRET_SHA256:\n");
	printf("----------------------------------------------------------\n");
	test_tls1_3_master_secrets(key_mgmt_hdl,
				   HSM_KEY_TYPE_ECC_NIST,
				   HSM_KEY_SIZE_ECC_NIST_256,
				   PERMITTED_ALGO_TLS1_3_MASTER_SECRET_SHA256,
				   HSM_KEY_DERIVATION_TLS1_3_MASTER_SECRET_SHA256,
				   &test_key_id,
				   key_store_id);

	delete_test_key(key_mgmt_hdl, test_key_id, 0);

	printf("\nECC_NIST & HSM_KEY_DERIVATION_TLS1_3_MASTER_SECRET_SHA384:\n");
	printf("----------------------------------------------------------\n");
	test_tls1_3_master_secrets(key_mgmt_hdl,
				   HSM_KEY_TYPE_ECC_NIST,
				   HSM_KEY_SIZE_ECC_NIST_384,
				   PERMITTED_ALGO_TLS1_3_MASTER_SECRET_SHA384,
				   HSM_KEY_DERIVATION_TLS1_3_MASTER_SECRET_SHA384,
				   &test_key_id,
				   key_store_id);

	delete_test_key(key_mgmt_hdl, test_key_id, 0);

	printf("\nECC_MONTGOMERY (255) & HSM KEY DERIVATION TLS 1.3 MS SHA256:\n");
	printf("-------------------------------------------------------------\n");
	test_tls1_3_master_secrets(key_mgmt_hdl,
				   HSM_KEY_TYPE_ECC_MONTGOMERY,
				   HSM_KEY_SIZE_ECC_MONTGOMERY_255,
				   PERMITTED_ALGO_TLS1_3_MASTER_SECRET_SHA256,
				   HSM_KEY_DERIVATION_TLS1_3_MASTER_SECRET_SHA256,
				   &test_key_id,
				   key_store_id);

	delete_test_key(key_mgmt_hdl, test_key_id, 0);

	printf("\nECC_MONTGOMERY (255) & HSM KEY DERIVATION TLS 1.3 MS SHA384:\n");
	printf("-------------------------------------------------------------\n");
	test_tls1_3_master_secrets(key_mgmt_hdl,
				   HSM_KEY_TYPE_ECC_MONTGOMERY,
				   HSM_KEY_SIZE_ECC_MONTGOMERY_255,
				   PERMITTED_ALGO_TLS1_3_MASTER_SECRET_SHA384,
				   HSM_KEY_DERIVATION_TLS1_3_MASTER_SECRET_SHA384,
				   &test_key_id,
				   key_store_id);

	delete_test_key(key_mgmt_hdl, test_key_id, 0);

	printf("\nECC MONTGOMERY (448) & HSM KEY DERIVATION TLS 1.3 MS SHA256:\n");
	printf("-------------------------------------------------------------\n");
	test_tls1_3_master_secrets(key_mgmt_hdl,
				   HSM_KEY_TYPE_ECC_MONTGOMERY,
				   HSM_KEY_SIZE_ECC_MONTGOMERY_448,
				   PERMITTED_ALGO_TLS1_3_MASTER_SECRET_SHA256,
				   HSM_KEY_DERIVATION_TLS1_3_MASTER_SECRET_SHA256,
				   &test_key_id,
				   key_store_id);

	delete_test_key(key_mgmt_hdl, test_key_id, 0);

	printf("\nECC MONTGOMERY (448) & HSM KEY DERIVATION TLS 1.3 MS SHA384:\n");
	printf("-------------------------------------------------------------\n");
	test_tls1_3_master_secrets(key_mgmt_hdl,
				   HSM_KEY_TYPE_ECC_MONTGOMERY,
				   HSM_KEY_SIZE_ECC_MONTGOMERY_448,
				   PERMITTED_ALGO_TLS1_3_MASTER_SECRET_SHA384,
				   HSM_KEY_DERIVATION_TLS1_3_MASTER_SECRET_SHA384,
				   &test_key_id,
				   key_store_id);

	delete_test_key(key_mgmt_hdl, test_key_id, 0);

	// Test TLS 1.3 Key Permitted algos
	printf("\nPermitted TLS 1.3 MS SHA ANY & HSM TLS 1.3 ES SHA256:\n");
	printf("-------------------------------------------------------\n");
	test_tls1_3_early_secrets(key_mgmt_hdl,
				  PERMITTED_ALGO_TLS1_3_MASTER_SECRET_SHA_ANY,
				  HSM_KEY_DERIVATION_TLS1_3_EARLY_SECRET_SHA256,
				  &test_key_id,
				  key_store_id);

	delete_test_key(key_mgmt_hdl, test_key_id, 0);

	printf("\nPermitted TLS 1.3 MS SHA ANY & HSM TLS 1.3 ES SHA384:\n");
	printf("-------------------------------------------------------\n");
	test_tls1_3_early_secrets(key_mgmt_hdl,
				  PERMITTED_ALGO_TLS1_3_MASTER_SECRET_SHA_ANY,
				  HSM_KEY_DERIVATION_TLS1_3_EARLY_SECRET_SHA384,
				  &test_key_id,
				  key_store_id);

	delete_test_key(key_mgmt_hdl, test_key_id, 0);

	printf("\nPermitted TLS 1.3 MS SHA ANY & HSM TLS 1.3 HS SHA256:\n");
	printf("-------------------------------------------------------\n");
	test_tls1_3_handshake_secrets(key_mgmt_hdl,
				      HSM_KEY_TYPE_ECC_NIST,
				      HSM_KEY_SIZE_ECC_NIST_256,
				      PERMITTED_ALGO_TLS1_3_MASTER_SECRET_SHA_ANY,
				      HSM_KEY_DERIVATION_TLS1_3_HANDSHAKE_SECRET_SHA256,
				      &test_key_id,
				      mbedtls_secret,
				      &mbedtls_secret_size,
				      key_store_id);

	delete_test_key(key_mgmt_hdl, test_key_id, 0);

	printf("\nPermitted TLS 1.3 MS SHA ANY & HSM TLS 1.3 HS SHA384:\n");
	printf("-------------------------------------------------------\n");
	test_tls1_3_handshake_secrets(key_mgmt_hdl,
				      HSM_KEY_TYPE_ECC_NIST,
				      HSM_KEY_SIZE_ECC_NIST_384,
				      PERMITTED_ALGO_TLS1_3_MASTER_SECRET_SHA_ANY,
				      HSM_KEY_DERIVATION_TLS1_3_HANDSHAKE_SECRET_SHA384,
				      &test_key_id,
				      mbedtls_secret,
				      &mbedtls_secret_size,
				      key_store_id);

	delete_test_key(key_mgmt_hdl, test_key_id, 0);

	printf("\nPermitted TLS 1.3 MS SHA ANY & HSM TLS 1.3 MS SHA256:\n");
	printf("-------------------------------------------------------\n");
	test_tls1_3_master_secrets(key_mgmt_hdl,
				   HSM_KEY_TYPE_ECC_NIST,
				   HSM_KEY_SIZE_ECC_NIST_256,
				   PERMITTED_ALGO_TLS1_3_MASTER_SECRET_SHA_ANY,
				   HSM_KEY_DERIVATION_TLS1_3_MASTER_SECRET_SHA256,
				   &test_key_id,
				   key_store_id);

	delete_test_key(key_mgmt_hdl, test_key_id, 0);

	printf("\nPermitted TLS 1.3 MS SHA ANY & HSM TLS 1.3 MS SHA384:\n");
	printf("-------------------------------------------------------\n");
	test_tls1_3_master_secrets(key_mgmt_hdl,
				   HSM_KEY_TYPE_ECC_NIST,
				   HSM_KEY_SIZE_ECC_NIST_384,
				   PERMITTED_ALGO_TLS1_3_MASTER_SECRET_SHA_ANY,
				   HSM_KEY_DERIVATION_TLS1_3_MASTER_SECRET_SHA384,
				   &test_key_id,
				   key_store_id);

	delete_test_key(key_mgmt_hdl, test_key_id, 0);

	printf("\n-----------------------------------------------------\n");
	printf("Test Complete");
	printf("\n-----------------------------------------------------\n");
}
#endif
