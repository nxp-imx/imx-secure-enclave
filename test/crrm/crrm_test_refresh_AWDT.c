// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crrm_api.h"

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>

#define TIMER_INFO_SIZE			16
#define SIGNATURE_LENGTH		64
#define REQ_DATA_SIZE			(sizeof(request_data) + SIGNATURE_LENGTH)
#define ECC_PRIVATE_KEY_SIZE		32

EVP_PKEY *create_evp_key_from_array(const uint8_t *key_data, size_t key_len)
{
	EVP_PKEY *pkey = NULL;
	EC_KEY *ec_key = NULL;

	// Create EC_KEY object with a specific curve
	ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); // Example: P-256
	if (!ec_key)
		return NULL;

	// Convert array to BIGNUM
	BIGNUM *priv_key_bn = BN_bin2bn(key_data, key_len, NULL);

	if (!priv_key_bn) {
		EC_KEY_free(ec_key);
		return NULL;
	}

	// Set private key
	if (!EC_KEY_set_private_key(ec_key, priv_key_bn)) {
		BN_free(priv_key_bn);
		EC_KEY_free(ec_key);
		return NULL;
	}

	// Derive public key from private key
	const EC_GROUP * group = EC_KEY_get0_group(ec_key);

	EC_POINT *pub_key = EC_POINT_new(group);

	if (!EC_POINT_mul(group, pub_key, priv_key_bn, NULL, NULL, NULL)) {
		EC_POINT_free(pub_key);
		BN_free(priv_key_bn);
		EC_KEY_free(ec_key);
		return NULL;
	}
	EC_KEY_set_public_key(ec_key, pub_key);

	//Print public key in hex
	char *pub_key_hex = EC_POINT_point2hex(group, pub_key,
					       POINT_CONVERSION_UNCOMPRESSED,
					       NULL);
	if (pub_key_hex) {
		printf("Public Key (hex): %s\n", pub_key_hex);
		OPENSSL_free(pub_key_hex);
	}

	// Wrap in EVP_PKEY
	pkey = EVP_PKEY_new();
	if (!EVP_PKEY_assign_EC_KEY(pkey, ec_key)) {
		EVP_PKEY_free(pkey);
		EC_KEY_free(ec_key);
		BN_free(priv_key_bn);
		EC_POINT_free(pub_key);
		return NULL;
	}

	// Cleanup
	BN_free(priv_key_bn);
	EC_POINT_free(pub_key);

	return pkey;
}

/*
 * msg is the message to sign.
 * msg_len is the length of message
 * raw_sign is the array to store generated signature
 */
int sign_message_raw_rs(const uint8_t *msg,
			size_t msg_len,
			uint8_t raw_sig[64])
{
	EVP_PKEY *pkey = NULL;
	EC_KEY *ec_key = NULL;
	ECDSA_SIG *ecdsa_sig = NULL;
	EVP_MD_CTX *mdctx = NULL;
	uint8_t digest[32];
	uint8_t *der_sig = NULL;
	const BIGNUM *r, *s;
	uint32_t der_len = 0;
	int32_t r_len = 0;
	int32_t s_len = 0;
	int32_t ret = 0;

	uint8_t private_key[ECC_PRIVATE_KEY_SIZE] = {0xfe, 0x14, 0xe8, 0x11,
						     0x59, 0x74, 0x4a, 0x75,
						     0x7f, 0x34, 0x79, 0x4e,
						     0xd2, 0x8b, 0x53, 0x39,
						     0x8a, 0x57, 0xc0, 0x6a,
						     0x9b, 0xd7, 0xa3, 0xf4,
						     0x3a, 0x3f, 0xc5, 0xa4,
						     0x78, 0x6e, 0x4b, 0x0d};
#if PUBLIC_KEY
	u8 p256_pub[] = {
		0x98, 0x49, 0x46, 0x6d, 0x79, 0x91, 0xca, 0x40,
		0x8d, 0x47, 0x1a, 0xfb, 0x3c, 0x9b, 0x65, 0xa9,
		0xf9, 0x0d, 0x02, 0xa1, 0x2a, 0x82, 0xf6, 0x3e,
		0x2c, 0x97, 0x9a, 0x84, 0x59, 0x6c, 0x0c, 0xdf,
		0x95, 0xde, 0x99, 0x51, 0x15, 0xcf, 0xe7, 0x4b,
		0x29, 0x21, 0x79, 0xe7, 0xfc, 0xf9, 0x7c, 0x5c,
		0x3e, 0x3c, 0x26, 0x19, 0x53, 0x46, 0x7a, 0xc2,
		0x35, 0x95, 0x76, 0xc6, 0x8c, 0x0b, 0x18, 0x97
	};
#endif

	pkey = create_evp_key_from_array(private_key, ECC_PRIVATE_KEY_SIZE);

	ec_key = EVP_PKEY_get1_EC_KEY(pkey);
	if (!ec_key) {
		printf("Failed to get EC_KEY from EVP_PKEY\n");
		goto cleanup;
	}

	// Hash the message
	if (!EVP_Digest(msg, msg_len, digest, NULL, EVP_sha256(), NULL)) {
		printf("Digest failed\n");
		goto cleanup;
	}

	// Sign the digest
	ecdsa_sig = ECDSA_do_sign(digest, 32, ec_key);
	if (!ecdsa_sig) {
		printf("ECDSA_do_sign failed\n");
		goto cleanup;
	}

	// Extract R and S
	ECDSA_SIG_get0(ecdsa_sig, &r, &s);

	// Convert R and S to fixed-size byte arrays
	r_len = BN_num_bytes(r);
	s_len = BN_num_bytes(s);
	if (r_len > 32 || s_len > 32) {
		printf("R or S too large\n");
		goto cleanup;
	}

	memset(raw_sig, 0, 64); // zero out
	BN_bn2binpad(r, raw_sig, 32);       // R at offset 0
	BN_bn2binpad(s, raw_sig + 32, 32);  // S at offset 32

	ret = 1; // success

cleanup:
	EC_KEY_free(ec_key);
	ECDSA_SIG_free(ecdsa_sig);
	EVP_MD_CTX_free(mdctx);
	return ret;
}

hsm_err_t crrm_test_refresh_AWDT(hsm_hdl_t crrm_hdl)
{
	op_get_nonce_args_t args = {0};
	op_refresh_AWDT_args_t targs = {0};
	signature_data *sdata = NULL;
	request_data *rdata = NULL;
	uint8_t info[NONCE_DATA_SIZE + TIMER_INFO_SIZE] = {0};
	uint8_t sign[SIGNATURE_LENGTH] = {0};
	size_t sig_len = 0;
	uint8_t timer_info_length = 0;
	hsm_err_t err;

	printf("-------------------\n");
	printf("REFRESH TIMER TEST:\n");
	printf("-------------------\n");

	args.nonce_size = NONCE_DATA_SIZE + TIMER_INFO_SIZE;
	args.nonce_addr = info;
	err = crrm_get_nonce(crrm_hdl, &args);

	args.info = (nonce_info *)args.nonce_addr;
	if (err)
		return err;

	// populate refresh AWDT API data
	targs.timer_id = 0;
	targs.new_timer_value = 200000;
	targs.pub_key_index = 0;

	// populate signature data
	sdata = (signature_data *)malloc(args.output_size + 8);
	sdata->timer_id = targs.timer_id;
	sdata->pub_key_index = targs.pub_key_index;
	sdata->new_timer_value = targs.new_timer_value;
	memcpy(sdata->nonce_data, args.info->nonce_data, NONCE_DATA_SIZE);

	timer_info_length = args.output_size - NONCE_DATA_SIZE;

	memcpy(sdata->timer_info, args.info->timer_info, timer_info_length);

	const uint8_t *message = (const uint8_t *)sdata;

	if (!sign_message_raw_rs(message,
				 args.output_size + 8,
			 sign)) {
		printf("Signature generation failed\n");
		return HSM_GENERAL_ERROR;
	}

#ifdef DEBUG
		printf("Signature (R || S):\n");
		for (int i = 0; i < 64; i++) {
			printf("%02X", sign[i]);
			if ((i + 1) % 32 == 0)
				printf(" "); // Separate R and S
		}
#endif

	rdata = (request_data *)malloc(REQ_DATA_SIZE);
	rdata->new_timer_value = targs.new_timer_value;
	rdata->signature_length = SIGNATURE_LENGTH;
	memcpy(rdata->signature, sign, SIGNATURE_LENGTH);

	targs.req_data_addr = (uint8_t *)rdata;
	targs.req_data_size = REQ_DATA_SIZE;

	err = crrm_refresh_AWDT(crrm_hdl, &targs);
	printf("---------------------\n");

	return err;
}
