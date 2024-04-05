// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#include <stdio.h>

#include "common.h"
#include "hsm_api.h"

#ifdef PSA_COMPLIANT
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
	in_content.hkdf_expand_algo = HSM_KEY_DERIVATION_HKDF_EXPAND_SHA256;
	in_content.prk_id = prk_id;
	in_content.derived_key_type = HSM_KEY_TYPE_AES;
	in_content.derived_key_bits_size = HSM_KEY_SIZE_AES_256;
	in_content.derived_key_lifetime = HSM_SE_KEY_STORAGE_VOLATILE;
	in_content.derived_key_usage = HSM_KEY_USAGE_ENCRYPT | HSM_KEY_USAGE_DECRYPT;
	in_content.derived_key_permitted_algo = PERMITTED_ALGO_ALL_CIPHER;
	in_content.derived_key_lifecycle = 0x0; // Current
	in_content.derived_key_id = 0x0; // Volatile Key, so ID chosen by FW
	in_content.prk_len = 0x0; // PRK Buffer not used.

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
#endif
