// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "hsm_api.h"
#include "common.h"
#include "nvm.h"

#define DATA_ID			0x12345678
#define ENC_DATA_ID		0x45321781

#define LINE_SIZE		12
#define LAST_IDX_IN_A_LINE	(LINE_SIZE - 1)
#define LOG_LEVEL		1

static void test_status(uint8_t *input, uint8_t *output, int len, char *result_str)
{
	int j;

	printf("Test Output for %s:\n", result_str);
#if (LOG_LEVEL > 0)
	for (j = 0; j < len; j++) {
		printf("0x%02x, ", output[j]);
		if (j % LINE_SIZE == 15)
			printf("\n");
	}
#endif
	if (memcmp(output, input, len) == 0) {
		printf("Result --> SUCCESS\n");
	} else {
		printf("Result --> FAILURE\n");
	}
}

static uint8_t  test_data[300] = {
	/* Note that the first 32 Bytes are the "Z" value
	 * that can be retrieved with hsm_sm2_get_z()
	 */
	0xB2, 0xE1, 0x4C, 0x5C, 0x79, 0xC6, 0xDF, 0x5B, 0x85, 0xF4, 0xFE, 0x7E,
	0xD8, 0xDB, 0x7A, 0x26,	0x2B, 0x9D, 0xA7, 0xE0, 0x7C, 0xCB, 0x0E, 0xA9,
	0xF4, 0x74, 0x7B, 0x8C, 0xCD, 0xA8, 0xA4, 0xF3, 0x6D, 0x65, 0x73, 0x73,
	0x61, 0x67, 0x65, 0x20, 0xB2, 0xE1, 0x4C, 0x5C, 0x79, 0xC6, 0xDF, 0x5B,
	0x85, 0xF4, 0xFE, 0x7E, 0xD8, 0xDB, 0x7A, 0x26, 0x2B, 0x9D, 0xA7, 0xE0,
	0x7C, 0xCB, 0x0E, 0xA9,	0xF4, 0x74, 0x7B, 0x8C, 0xCD, 0xA8, 0xA4, 0xF3,
	0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20,	0xB2, 0xE1, 0x4C, 0x5C,
	0x79, 0xC6, 0xDF, 0x5B, 0x85, 0xF4, 0xFE, 0x7E, 0xD8, 0xDB, 0x7A, 0x26,
	0x2B, 0x9D, 0xA7, 0xE0, 0x7C, 0xCB, 0x0E, 0xA9, 0xF4, 0x74, 0x7B, 0x8C,
	0xCD, 0xA8, 0xA4, 0xF3,	0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20,
	0xB2, 0xE1, 0x4C, 0x5C, 0x79, 0xC6, 0xDF, 0x5B, 0x85, 0xF4, 0xFE, 0x7E,
	0xD8, 0xDB, 0x7A, 0x26, 0x2B, 0x9D, 0xA7, 0xE0, 0x7C, 0xCB, 0x0E, 0xA9,
	0xF4, 0x74, 0x7B, 0x8C, 0xCD, 0xA8, 0xA4, 0xF3, 0x6D, 0x65, 0x73, 0x73,
	0x61, 0x67, 0x65, 0x20,	0xB2, 0xE1, 0x4C, 0x5C, 0x79, 0xC6, 0xDF, 0x5B,
	0x85, 0xF4, 0xFE, 0x7E, 0xD8, 0xDB, 0x7A, 0x26,	0x2B, 0x9D, 0xA7, 0xE0,
	0x7C, 0xCB, 0x0E, 0xA9, 0xF4, 0x74, 0x7B, 0x8C, 0xCD, 0xA8, 0xA4, 0xF3,
	0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0xB2, 0xE1, 0x4C, 0x5C,
	0x79, 0xC6, 0xDF, 0x5B,	0x85, 0xF4, 0xFE, 0x7E, 0xD8, 0xDB, 0x7A, 0x26,
	0x2B, 0x9D, 0xA7, 0xE0, 0x7C, 0xCB, 0x0E, 0xA9,	0xF4, 0x74, 0x7B, 0x8C,
	0xCD, 0xA8, 0xA4, 0xF3, 0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20,
	0xB2, 0xE1, 0x4C, 0x5C, 0x79, 0xC6, 0xDF, 0x5B, 0x85, 0xF4, 0xFE, 0x7E,
	0xD8, 0xDB, 0x7A, 0x26,	0x2B, 0x9D, 0xA7, 0xE0, 0x7C, 0xCB, 0x0E, 0xA9,
	0xF4, 0x74, 0x7B, 0x8C, 0xCD, 0xA8, 0xA4, 0xF3,	0x6D, 0x65, 0x73, 0x73,
	0x61, 0x67, 0x65, 0x20, 0xB2, 0xE1, 0x4C, 0x5C, 0x79, 0xC6, 0xDF, 0x5B,
	0x85, 0xF4, 0xFE, 0x7E, 0xD8, 0xDB, 0x7A, 0x26, 0x2B, 0x9D, 0xA7, 0xE0,
};

static uint8_t test_plain_data[64] = {
	0xB2, 0xE1, 0x4C, 0x5C, 0x79, 0xC6, 0xDF, 0x5B, 0x85, 0xF4, 0xFE, 0x7E,
	0xD8, 0xDB, 0x7A, 0x26,	0x2B, 0x9D, 0xA7, 0xE0, 0x7C, 0xCB, 0x0E, 0xA9,
	0xF4, 0x74, 0x7B, 0x8C, 0xCD, 0xA8, 0xA4, 0xF3, 0x6D, 0x65, 0x73, 0x73,
	0x61, 0x67, 0x65, 0x20, 0xB2, 0xE1, 0x4C, 0x5C, 0x79, 0xC6, 0xDF, 0x5B,
	0x85, 0xF4, 0xFE, 0x7E, 0xD8, 0xDB, 0x7A, 0x26, 0x2B, 0x9D, 0xA7, 0xE0,
	0x7C, 0xCB, 0x0E, 0xA9,
};

static uint8_t iv_data[16] = {
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
};

uint8_t recieved_data[300];
static uint8_t retrieved_enc_data[256]; //More buffer than needed

static uint8_t is_buff_empty(uint8_t *data_buff, uint32_t size)
{
	uint8_t res = 0;

	for (uint32_t i = 0; i < size; i++)
		res |= data_buff[i];

	return res;
}

void data_storage_test(hsm_hdl_t key_store_hdl, int arg)
{
	hsm_hdl_t data_storage_hdl;
	op_data_storage_args_t data_storage_args;
	hsm_err_t err;
	int j;
	uint32_t size = arg ? arg : sizeof(test_data);

#ifdef SECONDARY_API_SUPPORTED
	printf("\n---------------------------------------------------\n");
	printf(" Secondary API Test: Data Storage Test\n");
	printf("---------------------------------------------------\n");

	memset(&data_storage_args, 0, sizeof(op_data_storage_args_t));
	data_storage_args.svc_flags = 0;
	data_storage_args.data = test_data;
	data_storage_args.data_size = size;
	data_storage_args.data_id = DATA_ID;
	data_storage_args.flags |= HSM_OP_DATA_STORAGE_FLAGS_STORE;
	err = hsm_data_ops(key_store_hdl, &data_storage_args);
	if (err) {
		printf("Err[Store]: 0x%x hsm_data_ops.\n", err);
		dump_firmware_log(get_hsm_session_hdl());
		return;
	}

	memset(&data_storage_args, 0, sizeof(op_data_storage_args_t));
	data_storage_args.svc_flags = 0;
	data_storage_args.data = recieved_data;
	data_storage_args.data_size = size;
	data_storage_args.data_id = DATA_ID;
	data_storage_args.flags |= HSM_OP_DATA_STORAGE_FLAGS_RETRIEVE;
	err = hsm_data_ops(key_store_hdl, &data_storage_args);
	if (err) {
		printf("Err[Re-Store]: 0x%x hsm_data_ops.\n", err);
		dump_firmware_log(get_hsm_session_hdl());
		return;
	}

#else
	printf("\n---------------------------------------------------\n");
	printf("Data Storage Test\n");
	printf("---------------------------------------------------\n");

	open_svc_data_storage_args_t args = {0};

	err = hsm_open_data_storage_service(key_store_hdl, &args,
			&data_storage_hdl);

	if (err) {
		printf("err: 0x%x hsm_open_data_storage_service hdl: 0x%08x\n",
				err, data_storage_hdl);
		return;
	}

	data_storage_args.data = test_data;
	data_storage_args.data_size = size;
	data_storage_args.data_id = DATA_ID;
	data_storage_args.flags |= HSM_OP_DATA_STORAGE_FLAGS_STORE;
	err = hsm_data_storage(data_storage_hdl, &data_storage_args);
	if (err) {
		printf("Err[Store]: 0x%x hsm_data_storage hdl: 0x%08x\n",
							err, data_storage_hdl);
		dump_firmware_log(get_hsm_session_hdl());
		return;
	}

	memset(&data_storage_args, 0, sizeof(op_data_storage_args_t));

	data_storage_args.flags = 0;
	data_storage_args.data = recieved_data;
	data_storage_args.data_size = size;
	data_storage_args.data_id = DATA_ID;
	data_storage_args.flags |= HSM_OP_DATA_STORAGE_FLAGS_RETRIEVE;
	err = hsm_data_storage(data_storage_hdl, &data_storage_args);
	if (err) {
		printf("Err[Re-Store]: 0x%x hsm_data_storage hdl: 0x%08x\n",
							err, data_storage_hdl);
		dump_firmware_log(get_hsm_session_hdl());
		return;
	}

	test_status(test_data, recieved_data, size,
			"SAB_DATA_STORAGE_REQ");

	err = hsm_close_data_storage_service(data_storage_hdl);
	if (err) {
		printf("err: 0x%x hsm_close_data_storage_service hdl: 0x%08x\n",
				err, data_storage_hdl);
		return;
	}
#endif
	test_status(test_data, recieved_data, size,
			"SAB_DATA_STORAGE_REQ");
	printf("---------------------------------------------------\n");
}

#ifdef PSA_COMPLIANT
static hsm_err_t generate_key(hsm_hdl_t key_mgmt_hdl,
			      hsm_key_type_t key_type,
			      hsm_key_group_t key_group,
			      hsm_op_key_gen_flags_t flags,
			      uint8_t *out_key,
			      uint16_t out_size,
			      hsm_key_lifetime_t key_lifetime,
			      hsm_key_usage_t key_usage,
			      hsm_permitted_algo_t permitted_algo,
			      hsm_bit_key_sz_t bit_key_sz,
			      hsm_key_lifecycle_t key_lifecycle,
			      uint32_t *key_identifier)
{
	op_generate_key_args_t key_gen_args = {0};

	memset(&key_gen_args, 0, sizeof(key_gen_args));

	key_gen_args.key_identifier = key_identifier;
	key_gen_args.out_size = out_size;
	key_gen_args.flags = flags;
	key_gen_args.key_group = key_group;
	key_gen_args.key_lifetime = key_lifetime;
	key_gen_args.key_usage = key_usage;
	key_gen_args.permitted_algo = permitted_algo;
	key_gen_args.bit_key_sz = bit_key_sz;
	key_gen_args.key_lifecycle = key_lifecycle;
	key_gen_args.key_type = key_type;
	key_gen_args.out_key = out_key;

	return hsm_generate_key(key_mgmt_hdl, &key_gen_args);
}

void enc_data_storage_test(hsm_hdl_t key_mgmt_hdl, hsm_hdl_t key_store_hdl)
{
	op_enc_data_storage_args_t enc_data_storage_args = {0};
	op_data_storage_args_t data_storage_args = {0};
	op_cipher_one_go_args_t cipher_args = {0};
	op_mac_one_go_args_t mac_args = {0};
	uint8_t deciphered_data[64] = {0};
	uint32_t enc_key_id = 0;
	uint32_t sign_key_id = 0;
	hsm_err_t err;

	printf("\n---------------------------------------------------\n");
	printf("Encrypted Data Storage API Test\n");
	printf("---------------------------------------------------\n");

	//Generate Key for Cipher operation
	err = generate_key(key_mgmt_hdl,
			   HSM_KEY_TYPE_AES,
			   25,
			   0,
			   NULL,
			   0,
			   HSM_SE_KEY_STORAGE_VOLATILE,
			   HSM_KEY_USAGE_ENCRYPT | HSM_KEY_USAGE_DECRYPT,
			   PERMITTED_ALGO_CBC_NO_PADDING,
			   HSM_KEY_SIZE_AES_256,
			   HSM_KEY_LIFECYCLE_OPEN,
			   &enc_key_id);

	if (err != HSM_NO_ERROR) {
		printf("\nhsm_generate_key (Encryption Key) err: 0x%x\n", err);
		goto out;
	}

	//Generate Key for Signing the data
	err = generate_key(key_mgmt_hdl,
			   HSM_KEY_TYPE_AES,
			   25,
			   0,
			   NULL,
			   0,
			   HSM_SE_KEY_STORAGE_VOLATILE,
			   HSM_KEY_USAGE_SIGN_MSG | HSM_KEY_USAGE_VERIFY_MSG,
			   PERMITTED_ALGO_CMAC,
			   HSM_KEY_SIZE_AES_256,
			   HSM_KEY_LIFECYCLE_OPEN,
			   &sign_key_id);

	if (err != HSM_NO_ERROR) {
		printf("\nhsm_generate_key (Signing Key) err: 0x%x\n", err);
		goto out;
	}

	// Store Data after encryption and signing
	memset(&enc_data_storage_args, 0, sizeof(enc_data_storage_args));

	enc_data_storage_args.svc_flags = 0;
	enc_data_storage_args.data = test_plain_data;
	enc_data_storage_args.data_size = sizeof(test_plain_data);
	enc_data_storage_args.data_id = ENC_DATA_ID;
	enc_data_storage_args.enc_algo = HSM_CIPHER_ONE_GO_ALGO_CBC;
	enc_data_storage_args.enc_key_id = enc_key_id;
	enc_data_storage_args.iv = iv_data;
	enc_data_storage_args.iv_size = sizeof(iv_data);
	enc_data_storage_args.sign_algo = PERMITTED_ALGO_CMAC;
	enc_data_storage_args.sign_key_id = sign_key_id;
	enc_data_storage_args.flags = HSM_OP_ENC_DATA_STORAGE_FLAGS_READ_ONCE;
	enc_data_storage_args.lifecycle = HSM_KEY_LIFECYCLE_OPEN;

	err = hsm_enc_data_ops(key_store_hdl, &enc_data_storage_args);
	if (err != HSM_NO_ERROR) {
		printf("hsm_enc_data_ops [STORE] err:0x%x\n", err);
		goto out;
	} else {
		printf("Data [Encrypted + Signed] stored. SUCCESS\n\n");
	}

	//Retrieve Encrypted and Signed Data stored in NVM
	memset(&data_storage_args, 0, sizeof(data_storage_args));
	memset(retrieved_enc_data, 0, sizeof(retrieved_enc_data));

	data_storage_args.svc_flags = 0;
	data_storage_args.data = retrieved_enc_data;
	data_storage_args.data_size = enc_data_storage_args.out_data_size;
	data_storage_args.data_id = ENC_DATA_ID;
	data_storage_args.flags |= HSM_OP_DATA_STORAGE_FLAGS_RETRIEVE;

	err = hsm_data_ops(key_store_hdl, &data_storage_args);
	if (err != HSM_NO_ERROR) {
		printf("hsm_data_ops [RETRIEVE] err:0x%x\n", err);
		goto out;
	} else {
		printf("Data [Encrypted + Signed] retrieved. SUCCESS\n\n");
		if (decode_enc_data_tlv(&data_storage_args))
			printf("\nDecode Encrypted Data TLV: Failed.\n");
	}

	//Signature Verification
	memset(&mac_args, 0, sizeof(mac_args));

	mac_args.key_identifier = sign_key_id;
	mac_args.payload = data_storage_args.payload;
	mac_args.mac = data_storage_args.signature;
	mac_args.payload_size = data_storage_args.payload_len;
	mac_args.mac_size = data_storage_args.signature_len;
	mac_args.flags = HSM_OP_MAC_ONE_GO_FLAGS_MAC_VERIFICATION;
	mac_args.algorithm = PERMITTED_ALGO_CMAC;

	err = hsm_do_mac(key_store_hdl, &mac_args);

	if (err != HSM_NO_ERROR) {
		printf("hsm_do_mac (Verification) err: 0x%x\n", err);
		goto out;
	}

	if (mac_args.verification_status !=
	    HSM_MAC_VERIFICATION_STATUS_SUCCESS) {
		printf("Fail: Signature Verification\n\n");
		goto out;
	} else {
		printf("Signature Verified. SUCCESS.\n\n");
	}

	//Decrypt the retrieved Encrypted user data
	memset(&cipher_args, 0, sizeof(cipher_args));
	memset(deciphered_data, 0, sizeof(deciphered_data));

	cipher_args.key_identifier = enc_key_id;
	cipher_args.iv = data_storage_args.iv;
	cipher_args.iv_size = data_storage_args.iv_len;
	cipher_args.cipher_algo = HSM_CIPHER_ONE_GO_ALGO_CBC;
	cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_DECRYPT;
	cipher_args.input = data_storage_args.ciphertext;
	cipher_args.output = deciphered_data;
	cipher_args.input_size = data_storage_args.ciphertext_len;
	cipher_args.output_size = sizeof(deciphered_data);

	err = hsm_do_cipher(key_store_hdl, &cipher_args);
	if (err != HSM_NO_ERROR) {
		printf("hsm_cipher_one_go (DECRYPT) err: 0x%x\n", err);
		goto out;
	}

	if (memcmp(test_plain_data, deciphered_data, sizeof(test_plain_data)) == 0)
		printf("Decrypted data matches stored Plain data. SUCCESS\n\n");
	else
		printf("Fail: Decrypted data doesn't match stored Plain data\n\n");

	/**
	 * Retrieve again, the encrypted and signed data previously stored in
	 * NVM. If Read Once flag, was set during storing the data, the stored
	 * data will be erased and overwritten with 0s.
	 */
	memset(&data_storage_args, 0, sizeof(data_storage_args));
	memset(retrieved_enc_data, 0, sizeof(retrieved_enc_data));

	data_storage_args.svc_flags = 0;
	data_storage_args.data = retrieved_enc_data;
	data_storage_args.data_size = enc_data_storage_args.out_data_size;
	data_storage_args.data_id = ENC_DATA_ID;
	data_storage_args.flags |= HSM_OP_DATA_STORAGE_FLAGS_RETRIEVE;

	err = hsm_data_ops(key_store_hdl, &data_storage_args);
	if (err != HSM_NO_ERROR) {
		printf("hsm_data_ops [RETRIEVE Again] err:0x%x\n", err);
		goto out;
	}

	if (!is_buff_empty(retrieved_enc_data, enc_data_storage_args.out_data_size))
		printf("Retrieved Again: Encrypted + Signed Data Empty. SUCCESS\n");
	else
		printf("Fail: Retrieved Again Encrypted + Signed Data not Empty\n");

out:
	printf("---------------------------------------------------\n");
}
#endif
