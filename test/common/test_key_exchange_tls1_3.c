// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#include <stdio.h>

#include "test_common.h"
#include "hsm_api.h"

#ifdef PSA_COMPLIANT
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
static void test_tls1_3_early_secrets(hsm_hdl_t key_mgmt_hdl)
{
	hsm_err_t err;
	in_content_tls13_args_t in_content = {0};
	op_key_exchange_args_t key_ex_args = {0};
	op_delete_key_args_t del_args = {0};
	uint32_t key_id = 0; //Private Key ID, ELE FW
	uint32_t output_key_buffer[TEST_TLS1_3_DERIVED_MAX_KEY_SIZE];

	/*********************Early Secrets - EXT Binder *********************/

	/* HKDF label related variables */
	unsigned char hkdf_label[TEST_TLS1_3_HKDF_LABEL_MAX_LEN];
	uint16_t hkdf_label_len = 0;
	/* expanded key len - 32 bytes */
	uint16_t length = BITS_TO_BYTES(HSM_KEY_SIZE_DERIVE_256);
	const unsigned char *label = test_tls13_label_ext_binder;
	uint8_t label_len = sizeof(test_tls13_label_ext_binder);
	const unsigned char *context = context_buffer;
	uint8_t context_len = sizeof(context_buffer);

	/* 1. Prepare Input Plaintext Context, without optional PSK */
	memset(&in_content, 0, sizeof(in_content_tls13_args_t));

	in_content.ver = 0x1;
	in_content.rsv = 0x0;
	in_content.keystore_id = TEST_KEYSTORE_ID;
	in_content.tls1_3_algo = HSM_KEY_DERIVATION_TLS1_3_EARLY_SECRET_SHA256;
	in_content.priv_key_id = key_id; // Ignored for Early Secrets.
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

	/* 5. Case 1.2. Export Derived/Output Key Buffer. */
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
	key_ex_args.output_sz = BITS_TO_BYTES(HSM_KEY_SIZE_DERIVE_256);
	key_ex_args.output = (uint8_t *)output_key_buffer;

	err = hsm_key_exchange(key_mgmt_hdl, &key_ex_args);
	printf("\nhsm_key_exchange [TLS 1.3 ES case #1.2] err: 0x%x\n", err);
	printf("\t--Derived Key ID: 0x%x\n", key_ex_args.out_derived_key_id);
	printf("\t--Salt Size: 0x%x\n", key_ex_args.out_salt_sz);
	printf("\n--Derived Key Buffer:\n");
	dump_hex(key_ex_args.output, key_ex_args.output_sz);

	if (err != HSM_NO_ERROR)
		goto out;

out:
	return;
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
					  hsm_bit_key_sz_t bit_key_sz)
{
	hsm_err_t err;
	in_content_tls13_args_t in_content = {0};
	op_key_exchange_args_t key_ex_args = {0};
	op_generate_key_args_t key_gen_args = {0};
	op_delete_key_args_t del_args = {0};
	uint32_t key_id = 0; //Private Key ID, ELE FW
	uint32_t output_key_buffer[TEST_TLS1_3_DERIVED_MAX_KEY_SIZE];

	/**************Handshake Secrets - Client HS traffic ***************/

	/* HKDF label related variables */
	unsigned char hkdf_label[TEST_TLS1_3_HKDF_LABEL_MAX_LEN];
	uint16_t hkdf_label_len = 0;
	/* expanded key len - 32 bytes */
	uint16_t length = BITS_TO_BYTES(HSM_KEY_SIZE_DERIVE_256);
	const unsigned char *label = test_tls13_label_client_handshake_traffic;
	uint8_t label_len = sizeof(test_tls13_label_client_handshake_traffic);
	const unsigned char *context = context_buffer;
	uint8_t context_len = sizeof(context_buffer);

	/* 1. Generate ELE Private Key for Key Agreement process */
	key_gen_args.key_identifier = &key_id;
	key_gen_args.key_group = 40;
	key_gen_args.key_lifetime = HSM_SE_KEY_STORAGE_VOLATILE;
	key_gen_args.key_usage = HSM_KEY_USAGE_DERIVE;
	key_gen_args.permitted_algo = HSM_KEY_DERIVATION_TLS1_3_HANDSHAKE_SECRET_SHA256;
	key_gen_args.flags = 0x0;
	key_gen_args.key_type = key_type;
	key_gen_args.bit_key_sz = bit_key_sz;
	key_gen_args.key_lifecycle = 0x0; // Current Device Lifecycle
	key_gen_args.out_key = NULL;
	key_gen_args.out_size = 0x0;

	err = hsm_generate_key(key_mgmt_hdl, &key_gen_args);
	printf("\nhsm_generate_key (KeyPair) err: 0x%x\n", err);

	/* 2. Prepare Input Plaintext Context for TLS 1.3, without optional PSK */
	memset(&in_content, 0, sizeof(in_content_tls13_args_t));

	in_content.ver = 0x1;
	in_content.rsv = 0x0;
	in_content.keystore_id = TEST_KEYSTORE_ID;
	in_content.tls1_3_algo = HSM_KEY_DERIVATION_TLS1_3_HANDSHAKE_SECRET_SHA256;
	in_content.priv_key_id = key_id;
	in_content.derived_key_type = HSM_KEY_TYPE_DERIVE;
	in_content.derived_key_bits_size = HSM_KEY_SIZE_DERIVE_256;
	in_content.derived_key_lifetime = HSM_SE_KEY_STORAGE_VOLATILE; // Volatile
	in_content.derived_key_usage = HSM_KEY_USAGE_DERIVE;
	in_content.derived_key_permitted_algo = HSM_KEY_DERIVATION_HKDF_EXPAND_SHA256;
	in_content.derived_key_lifecycle = 0x0; // Current
	in_content.derived_key_id = 0x0; // Volatile Key, so ID chosen by FW
	in_content.psk_len = 0x0; // Optional PSK not used.

	/* 3. Prepare User Fixed Info or HKDF label */
	memset(hkdf_label, 0, sizeof(hkdf_label));
	tls13_hkdf_label_encode(length,
				label, label_len,
				context, context_len,
				hkdf_label, &hkdf_label_len);

	/* 4. Case 1.1. Derived Key stored in ELE FW. */
	memset(&key_ex_args, 0, sizeof(op_key_exchange_args_t));

	key_ex_args.flags = HSM_OP_KEY_EXCHANGE_FLAGS_INPUT_PLAINTEXT_CONTENT;
	key_ex_args.in_content_sz = sizeof(in_content_tls13_args_t);
	key_ex_args.in_content = (uint8_t *)(&in_content);
	key_ex_args.in_pub_buffer_sz = sizeof(public_buffer);
	key_ex_args.in_pub_buffer = public_buffer;
	key_ex_args.user_fixed_info_sz = hkdf_label_len;
	key_ex_args.user_fixed_info = (uint8_t *)hkdf_label;
	key_ex_args.output_sz = 0;
	key_ex_args.output = NULL;

	err = hsm_key_exchange(key_mgmt_hdl, &key_ex_args);
	printf("\nhsm_key_exchange [TLS 1.3 HS case  #1.1] err: 0x%x\n", err);
	printf("\t--Derived Key ID: 0x%x\n", key_ex_args.out_derived_key_id);
	printf("\t--Salt Size: 0x%x\n", key_ex_args.out_salt_sz);
	if (err != HSM_NO_ERROR)
		goto out;

	/* 5. Delete Derived Key */
	memset(&del_args, 0, sizeof(del_args));

	del_args.key_identifier = key_ex_args.out_derived_key_id;
	del_args.flags = 0;
	err = hsm_delete_key(key_mgmt_hdl, &del_args);
	if (err != HSM_NO_ERROR)
		printf("hsm_delete_key (Derived #1) ret: 0x%x\n", err);

	/* 6. Case 1.2. Export Derived/Output Key Buffer. */
	memset(&key_ex_args, 0, sizeof(op_key_exchange_args_t));
	memset(output_key_buffer, 0, sizeof(output_key_buffer));

	key_ex_args.flags = HSM_OP_KEY_EXCHANGE_FLAGS_INPUT_PLAINTEXT_CONTENT |
			    HSM_OP_KEY_EXCHANGE_FLAGS_RETURN_OUTPUT;
	key_ex_args.in_content_sz = sizeof(in_content_tls13_args_t);
	key_ex_args.in_content = (uint8_t *)(&in_content);
	key_ex_args.in_pub_buffer_sz = sizeof(public_buffer);
	key_ex_args.in_pub_buffer = public_buffer;
	key_ex_args.user_fixed_info_sz = hkdf_label_len;
	key_ex_args.user_fixed_info = (uint8_t *)hkdf_label;
	key_ex_args.output_sz = BITS_TO_BYTES(HSM_KEY_SIZE_DERIVE_256);
	key_ex_args.output = (uint8_t *)output_key_buffer;

	err = hsm_key_exchange(key_mgmt_hdl, &key_ex_args);
	printf("\nhsm_key_exchange [TLS 1.3 HS case #1.2] err: 0x%x\n", err);
	printf("\t--Derived Key ID: 0x%x\n", key_ex_args.out_derived_key_id);
	printf("\t--Salt Size: 0x%x\n", key_ex_args.out_salt_sz);
	printf("\n--Derived Key Buffer:\n");
	dump_hex(key_ex_args.output, key_ex_args.output_sz);

	if (err != HSM_NO_ERROR)
		goto out;

	/* 7. Delete the Generated test Key */
	memset(&del_args, 0, sizeof(del_args));

	del_args.key_identifier = key_id;
	del_args.flags = 0;
	err = hsm_delete_key(key_mgmt_hdl, &del_args);
	if (err != HSM_NO_ERROR)
		printf("hsm_delete_key (Generated) ret: 0x%x\n", err);
out:
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
				       hsm_bit_key_sz_t bit_key_sz)
{
	hsm_err_t err;
	in_content_tls13_args_t in_content = {0};
	op_key_exchange_args_t key_ex_args = {0};
	op_generate_key_args_t key_gen_args = {0};
	op_delete_key_args_t del_args = {0};
	uint32_t key_id = 0; //Private Key ID, ELE FW
	uint32_t output_key_buffer[TEST_TLS1_3_DERIVED_MAX_KEY_SIZE];

	/**************Master Secrets - Client application traffic ***************/

	/* HKDF label related variables */
	unsigned char hkdf_label[TEST_TLS1_3_HKDF_LABEL_MAX_LEN];
	uint16_t hkdf_label_len = 0;
	/* expanded key len - 32 bytes */
	uint16_t length = BITS_TO_BYTES(HSM_KEY_SIZE_DERIVE_256);
	const unsigned char *label = test_tls13_label_client_application_traffic;
	uint8_t label_len = sizeof(test_tls13_label_client_application_traffic);
	const unsigned char *context = context_buffer;
	uint8_t context_len = sizeof(context_buffer);

	/* 1. Generate ELE Private Key for Key Agreement process */
	key_gen_args.key_identifier = &key_id;
	key_gen_args.key_group = 40;
	key_gen_args.key_lifetime = HSM_SE_KEY_STORAGE_VOLATILE;
	key_gen_args.key_usage = HSM_KEY_USAGE_DERIVE;
	key_gen_args.permitted_algo = HSM_KEY_DERIVATION_TLS1_3_MASTER_SECRET_SHA256;
	key_gen_args.flags = 0x0;
	key_gen_args.key_type = key_type;
	key_gen_args.bit_key_sz = bit_key_sz;
	key_gen_args.key_lifecycle = 0x0; // Current Device Lifecycle
	key_gen_args.out_key = NULL;
	key_gen_args.out_size = 0x0;

	err = hsm_generate_key(key_mgmt_hdl, &key_gen_args);
	printf("\nhsm_generate_key (KeyPair) err: 0x%x\n", err);

	/* 2. Prepare Input Plaintext Context for TLS 1.3, without optional PSK */
	memset(&in_content, 0, sizeof(in_content_tls13_args_t));

	in_content.ver = 0x1;
	in_content.rsv = 0x0;
	in_content.keystore_id = TEST_KEYSTORE_ID;
	in_content.tls1_3_algo = HSM_KEY_DERIVATION_TLS1_3_MASTER_SECRET_SHA256;
	in_content.priv_key_id = key_id;
	in_content.derived_key_type = HSM_KEY_TYPE_DERIVE;
	in_content.derived_key_bits_size = HSM_KEY_SIZE_DERIVE_256;
	in_content.derived_key_lifetime = HSM_SE_KEY_STORAGE_VOLATILE; // Volatile
	in_content.derived_key_usage = HSM_KEY_USAGE_DERIVE;
	in_content.derived_key_permitted_algo = HSM_KEY_DERIVATION_HKDF_EXPAND_SHA256;
	in_content.derived_key_lifecycle = 0x0; // Current
	in_content.derived_key_id = 0x0; // Volatile Key, so ID chosen by FW
	in_content.psk_len = 0x0; // Optional PSK not used.

	/* 3. Prepare User Fixed Info or HKDF label */
	memset(hkdf_label, 0, sizeof(hkdf_label));
	tls13_hkdf_label_encode(length,
				label, label_len,
				context, context_len,
				hkdf_label, &hkdf_label_len);

	/* 4. Case 1.1. Derived Key stored in ELE FW. */
	memset(&key_ex_args, 0, sizeof(op_key_exchange_args_t));

	key_ex_args.flags = HSM_OP_KEY_EXCHANGE_FLAGS_INPUT_PLAINTEXT_CONTENT;
	key_ex_args.in_content_sz = sizeof(in_content_tls13_args_t);
	key_ex_args.in_content = (uint8_t *)(&in_content);
	key_ex_args.in_pub_buffer_sz = sizeof(public_buffer);
	key_ex_args.in_pub_buffer = public_buffer;
	key_ex_args.user_fixed_info_sz = hkdf_label_len;
	key_ex_args.user_fixed_info = (uint8_t *)hkdf_label;
	key_ex_args.output_sz = 0;
	key_ex_args.output = NULL;

	err = hsm_key_exchange(key_mgmt_hdl, &key_ex_args);
	printf("\nhsm_key_exchange [TLS 1.3 MS case #1.1] err: 0x%x\n", err);
	printf("\t--Derived Key ID: 0x%x\n", key_ex_args.out_derived_key_id);
	printf("\t--Salt Size: 0x%x\n", key_ex_args.out_salt_sz);
	if (err != HSM_NO_ERROR)
		goto out;

	/* 5. Delete Derived Key */
	memset(&del_args, 0, sizeof(del_args));

	del_args.key_identifier = key_ex_args.out_derived_key_id;
	del_args.flags = 0;
	err = hsm_delete_key(key_mgmt_hdl, &del_args);
	if (err != HSM_NO_ERROR)
		printf("hsm_delete_key (Derived #1) ret: 0x%x\n", err);

	/* 6. Case 1.2. Export Derived/Output Key Buffer. */
	memset(&key_ex_args, 0, sizeof(op_key_exchange_args_t));
	memset(output_key_buffer, 0, sizeof(output_key_buffer));

	key_ex_args.flags = HSM_OP_KEY_EXCHANGE_FLAGS_INPUT_PLAINTEXT_CONTENT |
			    HSM_OP_KEY_EXCHANGE_FLAGS_RETURN_OUTPUT;
	key_ex_args.in_content_sz = sizeof(in_content_tls13_args_t);
	key_ex_args.in_content = (uint8_t *)(&in_content);
	key_ex_args.in_pub_buffer_sz = sizeof(public_buffer);
	key_ex_args.in_pub_buffer = public_buffer;
	key_ex_args.user_fixed_info_sz = hkdf_label_len;
	key_ex_args.user_fixed_info = (uint8_t *)hkdf_label;
	key_ex_args.output_sz = BITS_TO_BYTES(HSM_KEY_SIZE_DERIVE_256);
	key_ex_args.output = (uint8_t *)output_key_buffer;

	err = hsm_key_exchange(key_mgmt_hdl, &key_ex_args);
	printf("\nhsm_key_exchange [TLS 1.3 MS case #1.2] err: 0x%x\n", err);
	printf("\t--Derived Key ID: 0x%x\n", key_ex_args.out_derived_key_id);
	printf("\t--Salt Size: 0x%x\n", key_ex_args.out_salt_sz);
	printf("\n--Derived Key Buffer:\n");
	dump_hex(key_ex_args.output, key_ex_args.output_sz);

	if (err != HSM_NO_ERROR)
		goto out;

	/* 7. Delete the Generated test Key */
	memset(&del_args, 0, sizeof(del_args));

	del_args.key_identifier = key_id;
	del_args.flags = 0;
	err = hsm_delete_key(key_mgmt_hdl, &del_args);
	if (err != HSM_NO_ERROR)
		printf("hsm_delete_key (Generated) ret: 0x%x\n", err);

out:
	return;
}

/**
 * TLS 1.3 tests for:
 *	- "Early Secrets",
 *	- "Handshake Secrets",
 *	- "Master Secrets"
 */
void key_exchange_test_tls1_3(hsm_hdl_t key_mgmt_hdl)
{
	printf("\n-----------------------------------------------------\n");
	printf("Key Exchange API tests - TLS 1.3");
	printf("\n-----------------------------------------------------\n");

	printf("\nECC_NIST & HSM_KEY_DERIVATION_TLS1_3_EARLY_SECRET_SHA256:\n");
	printf("---------------------------------------------------------\n");
	test_tls1_3_early_secrets(key_mgmt_hdl);

	printf("\nECC_NIST & HSM_KEY_DERIVATION_TLS1_3_HANDSHAKE_SECRET_SHA256:\n");
	printf("-------------------------------------------------------------\n");
	test_tls1_3_handshake_secrets(key_mgmt_hdl,
				      HSM_KEY_TYPE_ECC_NIST,
				      HSM_KEY_SIZE_ECC_NIST_256);

	printf("\nECC_MONTGOMERY & HSM_KEY_DERIVATION_TLS1_3_HANDSHAKE_SECRET_SHA256:\n");
	printf("-------------------------------------------------------------------\n");
	test_tls1_3_handshake_secrets(key_mgmt_hdl,
				      HSM_KEY_TYPE_ECC_MONTGOMERY,
				      HSM_KEY_SIZE_ECC_MONTGOMERY_255);

	printf("\nECC_NIST & HSM_KEY_DERIVATION_TLS1_3_MASTER_SECRET_SHA256:\n");
	printf("----------------------------------------------------------\n");
	test_tls1_3_master_secrets(key_mgmt_hdl,
				   HSM_KEY_TYPE_ECC_NIST,
				   HSM_KEY_SIZE_ECC_NIST_256);

	printf("\nECC_MONTGOMERY & HSM_KEY_DERIVATION_TLS1_3_MASTER_SECRET_SHA256:\n");
	printf("----------------------------------------------------------------\n");
	test_tls1_3_master_secrets(key_mgmt_hdl,
				   HSM_KEY_TYPE_ECC_MONTGOMERY,
				   HSM_KEY_SIZE_ECC_MONTGOMERY_255);

	printf("\n-----------------------------------------------------\n");
	printf("Test Complete");
	printf("\n-----------------------------------------------------\n");
}
#endif
