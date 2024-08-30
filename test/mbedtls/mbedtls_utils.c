// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */
#ifdef PSA_COMPLIANT
#include "mbedtls_utils.h"

#include <mbedtls/ecdh.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/aes.h>
#include <mbedtls/ssl.h>

/* Needed for mbedtls_ecdh_compute_shared */
static int my_mbedtls_rand(void *rng_state, unsigned char *output, size_t len)
{
	op_get_random_args_t args = {0};
	uint32_t ret;
	int res = -1;

	(void)rng_state;

	do {
		args.output = output;
		args.random_size = len;

		ret = hsm_do_rng(get_hsm_session_hdl(), &args);
		if (ret != HSM_NO_ERROR)
			break;

		res = 0;
	} while (0);

	return res;
}

static uint32_t mbedtls_key_type_from_hsm_key_type(uint16_t key_size_bits,
						   uint16_t hsm_key_type)
{
	uint32_t mbedtls_type = MBEDTLS_ECP_DP_NONE;

	switch (hsm_key_type) {
	case HSM_KEY_TYPE_ECC_NIST:
		if (key_size_bits == 256)
			mbedtls_type = MBEDTLS_ECP_DP_SECP256R1;
		else if (key_size_bits == 384)
			mbedtls_type = MBEDTLS_ECP_DP_SECP384R1;
		else if (key_size_bits == 521)
			mbedtls_type = MBEDTLS_ECP_DP_SECP521R1;

		break;
	case HSM_KEY_TYPE_ECC_BP_R1:
		if (key_size_bits == 256)
			mbedtls_type = MBEDTLS_ECP_DP_BP256R1;
		else if (key_size_bits == 384)
			mbedtls_type = MBEDTLS_ECP_DP_BP384R1;

		break;
	default:
		break;
	}

	return mbedtls_type;
}

static uint32_t mbedtls_hash_algo_from_hsm_hash_algo(uint32_t hsm_hash_algo)
{
	uint32_t mbedtls_hash_algo = MBEDTLS_MD_NONE;

	switch (hsm_hash_algo) {
	case HSM_HASH_ALGO_SHA_256:
		mbedtls_hash_algo = MBEDTLS_MD_SHA256;
		break;
	case HSM_HASH_ALGO_SHA_384:
		mbedtls_hash_algo = MBEDTLS_MD_SHA384;
		break;
	default:
		break;
	}

	return mbedtls_hash_algo;
}

static uint32_t mbedtls_get_hash_len(uint32_t hsm_hash_algo)
{
	uint32_t hash_len = 0x0U;

	switch (hsm_hash_algo) {
	case HSM_HASH_ALGO_SHA_256:
		hash_len = HSM_HASH_ALGO_SHA_256_SIZE;
		break;
	case HSM_HASH_ALGO_SHA_384:
		hash_len = HSM_HASH_ALGO_SHA_384_SIZE;
		break;
	default:
		break;
	}

	return hash_len;
}

uint32_t my_mbedtls_hkdf(uint32_t hash_algo,
			 uint8_t *ikm, uint32_t ikm_size,
			 uint8_t *salt, uint32_t salt_size,
			 uint8_t *info, uint32_t info_size,
			 uint8_t *okm, uint32_t okm_size)
{
	uint32_t ret = FAILURE;
	int res = -1;
	uint32_t mbedtls_hash_algo = 0x0U;
	const mbedtls_md_info_t *md = NULL;

	do {
		mbedtls_hash_algo = mbedtls_hash_algo_from_hsm_hash_algo(hash_algo);
		if (mbedtls_hash_algo == MBEDTLS_MD_NONE) {
			printf("%s: unsupported hash algo 0x%x\n",
			       __func__, hash_algo);
			break;
		}

		/* Set md info */
		md = mbedtls_md_info_from_type(mbedtls_hash_algo);
		if (!md) {
			printf("%s: mbedtls_md_info_from_type return NULL\n",
			       __func__);
			break;
		}

		/* Execute hkdf */
		res = mbedtls_hkdf(md, salt, salt_size, ikm, ikm_size,
				   info, info_size, okm, okm_size);
		if (res != 0) {
			printf("%s: mbedtls_hkdf failed with 0x%x\n",
			       __func__, res);
			break;
		}

		ret = SUCCESS;
	} while (0);

	if (ret)
		printf("%s: FAILURE\n", __func__);

	return ret;
}

uint32_t my_mbedtls_hkdf_expand(uint32_t hash_algo,
				uint8_t *prk, uint32_t prk_size,
				uint8_t *fixed_info, uint32_t fixed_info_size,
				uint8_t *okm, uint32_t okm_size)
{
	uint32_t ret = FAILURE;
	int res = -1;
	uint32_t mbedtls_hash_algo = 0x0U;
	const mbedtls_md_info_t *md = NULL;

	do {
		mbedtls_hash_algo = mbedtls_hash_algo_from_hsm_hash_algo(hash_algo);
		if (mbedtls_hash_algo == MBEDTLS_MD_NONE) {
			printf("%s: unsupported hash algo 0x%x\n",
			       __func__, hash_algo);
			break;
		}

		/* Set md info */
		md = mbedtls_md_info_from_type(mbedtls_hash_algo);
		if (!md) {
			printf("%s: mbedtls_md_info_from_type return NULL\n",
			       __func__);
			break;
		}

		/* Execute hkdf */
		res = mbedtls_hkdf_expand(md, prk, prk_size, fixed_info,
					  fixed_info_size, okm, okm_size);
		if (res != 0) {
			printf("%s: mbedtls_hkdf_expand failed with 0x%x\n",
			       __func__, res);
			break;
		}

		ret = SUCCESS;
	} while (0);

	if (ret)
		printf("%s: FAILURE\n", __func__);

	return ret;
}

uint32_t my_mbedtls_hkdf_extract(uint32_t hash_algo,
				 uint8_t *salt, uint32_t salt_size,
				 uint8_t *ikm, uint32_t ikm_size,
				 uint8_t *prk, uint32_t prk_size)
{
	uint32_t ret = FAILURE;
	int res = -1;
	uint32_t mbedtls_hash_algo = 0x0U;
	const mbedtls_md_info_t *md = NULL;

	do {
		mbedtls_hash_algo = mbedtls_hash_algo_from_hsm_hash_algo(hash_algo);
		if (mbedtls_hash_algo == MBEDTLS_MD_NONE) {
			printf("%s: unsupported hash algo 0x%x\n",
			       __func__, hash_algo);
			break;
		}

		/* Set md info */
		md = mbedtls_md_info_from_type(mbedtls_hash_algo);
		if (!md) {
			printf("%s: mbedtls_md_info_from_type return NULL\n",
			       __func__);
			break;
		}

		/* Check PRK size to avoid memory issue as not checked by MbedTLS */
		if (prk_size != mbedtls_get_hash_len(hash_algo)) {
			printf("%s: invalid prk size 0x%x\n", __func__, prk_size);
			break;
		}

		/* Execute hkdf */
		res = mbedtls_hkdf_extract(md, salt, salt_size, ikm, ikm_size, prk);
		if (res != 0) {
			printf("%s: mbedtls_hkdf_extract failed with 0x%x\n",
			       __func__, res);
			break;
		}

		ret = SUCCESS;
	} while (0);

	if (ret)
		printf("%s: FAILURE\n", __func__);

	return ret;
}

uint32_t my_mbedtls_ecdh(uint16_t key_size_bits, uint16_t key_type,
			 uint8_t *pub_key, uint32_t pub_key_size,
			 uint8_t *priv_key, uint32_t priv_key_size,
			 uint8_t *ecdh, uint32_t *ecdh_size)
{
	uint32_t ret = FAILURE;
	int res = -1;
	uint32_t mbedtls_type = 0x0U;
	uint32_t z_size = 0x0U;
	uint32_t mbed_pub_key_size = pub_key_size + 1;
	uint8_t mbed_pub_key[mbed_pub_key_size];
	mbedtls_ecp_group grp;
	mbedtls_ecp_point fw_pub_key;
	mbedtls_ecp_keypair mbed_priv_key;
	mbedtls_mpi z_shared_secret;

	do {
		mbedtls_type = mbedtls_key_type_from_hsm_key_type(key_size_bits,
								  key_type);
		if (mbedtls_type == MBEDTLS_ECP_DP_NONE) {
			printf("%s: unsupported key size bits %d key type 0x%x\n",
			       __func__, key_size_bits, key_type);
			break;
		}

		/* Prepare public key */
		memset(&grp, 0, sizeof(grp));
		res = mbedtls_ecp_group_load(&grp, mbedtls_type);
		if (res != 0) {
			printf("%s: mbedtls_ecp_group_load failed with 0x%x\n",
			       __func__, res);
			break;
		}

		/* Prepare public key, a 0x04 leading byte must be added */
		mbed_pub_key[0] = 0x04;
		memcpy(mbed_pub_key + 1, pub_key, pub_key_size);

		/* Load public key from buffer */
		mbedtls_ecp_point_init(&fw_pub_key);
		res = mbedtls_ecp_point_read_binary(&grp, &fw_pub_key,
						    mbed_pub_key, mbed_pub_key_size);
		if (res != 0) {
			printf("%s: mbedtls_ecp_point_read_binary failed with 0x%x\n",
			       __func__, res);
			break;
		}

		/* Check public key */
		res = mbedtls_ecp_check_pubkey(&grp, &fw_pub_key);
		if (res != 0) {
			printf("%s: mbedtls_ecp_check_pubkey failed with 0x%x\n",
			       __func__, res);
			break;
		}

		/* Prepare private key */
		mbedtls_ecp_keypair_init(&mbed_priv_key);
		res = mbedtls_ecp_group_load(&mbed_priv_key.private_grp, mbedtls_type);
		if (res != 0) {
			printf("%s: mbedtls_ecp_group_load failed with 0x%x\n",
			       __func__, res);
			break;
		}

		/* Load private key from buffer */
		res = mbedtls_ecp_read_key(mbed_priv_key.private_grp.id,
					   &mbed_priv_key, priv_key, priv_key_size);
		if (res != 0) {
			printf("%s: mbedtls_ecp_read_key failed with 0x%x\n",
			       __func__, res);
			break;
		}

		/* Check private key */
		res = mbedtls_ecp_check_privkey(&mbed_priv_key.private_grp,
						&mbed_priv_key.private_d);
		if (res != 0) {
			printf("%s: mbedtls_ecp_check_privkey failed with 0x%x\n",
			       __func__, res);
			break;
		}

		/* Compute ECDH */
		mbedtls_mpi_init(&z_shared_secret);
		res = mbedtls_ecdh_compute_shared(&grp, &z_shared_secret,
						  &fw_pub_key, &mbed_priv_key.private_d,
						  my_mbedtls_rand, NULL);
		if (res != 0) {
			printf("%s: mbedtls_ecdh_compute_shared failed with 0x%x\n",
			       __func__, res);
			break;
		}

		if (key_size_bits == 521) {
			/**
			 * 521 bits specific case,
			 * z_shared_secret.private_n equals 9 => 0 padding ?
			 */
			z_size = 66;
		} else {
			z_size = 8 * z_shared_secret.private_n;
		}

		if (*ecdh_size < z_size) {
			printf("%s: invalid ecdh size 0x%x (should be 0x%x)\n",
			       __func__, *ecdh_size, z_size);
			break;
		}

		/**
		 * MbedTLS stores mpi in little endian.
		 * ESH, ELE FW, Test Vectors use big endian
		 */
		memcpy(ecdh, (uint8_t *)z_shared_secret.private_p, z_size);
		bytes_swap(ecdh, z_size);

		mbedtls_ecp_group_free(&grp);
		mbedtls_ecp_point_free(&fw_pub_key);
		mbedtls_ecp_keypair_free(&mbed_priv_key);
		mbedtls_mpi_free(&z_shared_secret);

		ret = SUCCESS;
	} while (0);

	/* Update correct ecdh size */
	*ecdh_size = z_size;

	if (ret)
		printf("%s: FAILURE\n", __func__);

	return ret;
}

static mbedtls_tls_prf_types mbedtls_get_tls12_prk(uint32_t hsm_tls12_algo)
{
	mbedtls_tls_prf_types tls12_prf = MBEDTLS_SSL_TLS_PRF_NONE;

	switch (HSM_HASH_ALGO_FROM_ALGO(hsm_tls12_algo)) {
	case HSM_HASH_ALGO_SHA_256:
		tls12_prf = MBEDTLS_SSL_TLS_PRF_SHA256;
		break;

	case HSM_HASH_ALGO_SHA_384:
		tls12_prf = MBEDTLS_SSL_TLS_PRF_SHA384;
		break;

	default:
		break;
	}

	return tls12_prf;
}

uint32_t my_mbedtls_tls12_prf(uint32_t hsm_tls12_algo, uint8_t *secret,
			      uint32_t secret_size, const char *label,
			      uint8_t *random, uint32_t random_size,
			      uint8_t *derived_secret, uint32_t derived_secret_size)
{
	uint32_t ret = FAILURE;
	int res = -1;
	mbedtls_tls_prf_types tls12_prf = mbedtls_get_tls12_prk(hsm_tls12_algo);

	res = mbedtls_ssl_tls_prf(tls12_prf, secret, secret_size,
				  (const char *)label, random, random_size,
				  derived_secret, derived_secret_size);
	if (res != 0)
		printf("%s: mbedtls_ssl_tls_prf failed with 0x%x\n",
		       __func__, res);
	else
		ret = SUCCESS;

	if (ret)
		printf("%s: FAILURE\n", __func__);

	return ret;
}

static uint8_t mbedtls_cipher_flag_from_hsm_cipher_flag(uint8_t hsm_cipher_flag)
{
	uint8_t mbedtls_cipher_flag = MBEDTLS_AES_DECRYPT;

	if (hsm_cipher_flag == HSM_CIPHER_ONE_GO_FLAGS_ENCRYPT)
		mbedtls_cipher_flag = MBEDTLS_AES_ENCRYPT;

	return mbedtls_cipher_flag;
}

uint32_t my_mbedtls_aes_cbc(uint32_t key_size_bits, uint8_t *key, uint8_t flag,
			    uint8_t *in, uint32_t in_size,
			    uint8_t *out, uint8_t *iv)
{
	uint32_t ret = FAILURE;
	int res = -1;
	uint8_t mbedtls_cipher_flag = mbedtls_cipher_flag_from_hsm_cipher_flag(flag);
	uint8_t local_iv[16]; /* Only 16 bytes IV are supported */
	mbedtls_aes_context aes_ctx;

	do {
		/* MbedTLS AES context init and setup */
		mbedtls_aes_init(&aes_ctx);

		res = mbedtls_aes_setkey_enc(&aes_ctx, key, key_size_bits);
		if (res != 0) {
			printf("%s: mbedtls_aes_setkey_enc failed with 0x%x\n",
			       __func__, res);
			break;
		}

		/* MbedTLS updates the IV content, use local variable */
		memcpy(local_iv, iv, 16);

		res = mbedtls_aes_crypt_cbc(&aes_ctx, mbedtls_cipher_flag,
					    in_size, local_iv, in, out);
		if (res != 0) {
			printf("%s: mbedtls_aes_crypt_cbc failed with 0x%x\n",
			       __func__, res);
			break;
		}

		mbedtls_aes_free(&aes_ctx);
		ret = SUCCESS;
	} while (0);

	if (ret)
		printf("%s: FAILURE\n", __func__);

	return ret;
}
#endif
