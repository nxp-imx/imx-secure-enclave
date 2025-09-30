/*
 *
 * Copyright 2023, 2025 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<fcntl.h>
#include<unistd.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include "hsm_api.h"
#include <openssl_testapi.h>
#include <pthread.h>

/* function to print the byte wise values at address of given length */
void HEXDUMP(unsigned char *buf, size_t sz)
{
	uint32_t i;
	printf("hex dump size: :%zu\n", sz);
	for (i = 0; i < (sz); i++) {
		printf("0x%02x, ", buf[i]);
		if (!(i%16))
			printf("\n");
	}
	printf("\n");
}

void BUFF_DUMP(char *str, unsigned char *buf, size_t sz)
{
	uint32_t i;
	printf("\n");
	printf("%s:hex dump size: %zu\n",str, sz);
	for (i = 0; i < (sz); i++) {
		printf("0x%02x, ", buf[i]);
		if ((i!=0) && !(i%16))
			printf("\n");
	}
	printf("\n");
	sleep(2);
}
/* compare data of two buffer */
int32_t compare_data(uint8_t *ori_data, uint8_t *dec_data,
		int32_t datalen)
{
	int32_t ret = -1;
	if (NULL != ori_data && NULL != dec_data)
		ret = memcmp(ori_data, dec_data, datalen);
	return ret;
}

/*! @brief compare data with  OpenSSL operation
 * params:
 * in: enc_dataB- Encrypted data buffer in sk_buffer form
 * in: plKey- plain Key in sk_buffer form
 * out: dec_dataB- Decrypted data buffer in sk_buffer form
 * in: aesParam- AES parameters used in encryption and decryption
 * return: success or failure
 */
#if 0
uint32_t openSSL_Decryption(struct sk_buffer *enc_dataB,
		struct sk_buffer *plKey,
		struct sk_buffer *dec_dataB,
		struct sk_aes_params *aesParam) {
	uint32_t status = SK_SUCCESS;
	int32_t rv, dec_len;
	AES_KEY dec_key;
	EVP_CIPHER_CTX *ctx;

	if (aesParam->mode == SK_AES_CBC) {
		AES_set_decrypt_key(plKey->buffer, (plKey->length)*8, &dec_key);

		AES_cbc_encrypt(enc_dataB->buffer, dec_dataB->buffer,
				enc_dataB->length,
				&dec_key, aesParam->aes_cbc.iv->buffer,
				AES_DECRYPT);
	} else if (aesParam->mode == SK_AES_CCM) {
		ctx = EVP_CIPHER_CTX_new();
#ifdef OPENSSL_APP_LOG
		printf("\nAES CCM Derypt:\n");
		printf("\nopen ssl dec Ciphertext:\n");
		BIO_dump_fp(stdout, enc_dataB->buffer, enc_dataB->length);
#endif
		ctx = EVP_CIPHER_CTX_new();
		/* Select cipher */
		if (plKey->length == 24)
			EVP_DecryptInit_ex(ctx, EVP_aes_192_ccm(), NULL, NULL, NULL);
		else if (plKey->length == 32)
			EVP_DecryptInit_ex(ctx, EVP_aes_256_ccm(), NULL, NULL, NULL);
		else if (plKey->length == 16)
			EVP_DecryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL);
		/* Set nonce length, omit for 96 bits */
		EVP_CIPHER_CTX_ctrl(ctx, 0x9, aesParam->aes_ccm.nonce->length, NULL);
#ifdef OPENSSL_APP_LOG
		printf("\nopen ssl dec MAC\n");
		BIO_dump_fp(stdout, aesParam->aes_ccm.mac->buffer, aesParam->aes_ccm.mac->length);
#endif

		/* Set expected tag value */
		EVP_CIPHER_CTX_ctrl(ctx, 0x11, aesParam->aes_ccm.mac->length, (void *)aesParam->aes_ccm.mac->buffer);
		/* Specify key and IV */
		EVP_DecryptInit_ex(ctx, NULL, NULL, plKey->buffer, aesParam->aes_ccm.nonce->buffer);
		if (aesParam->aes_ccm.aad->buffer != NULL) {
			/* Set ciphertext length: only needed if we have AAD */
			EVP_DecryptUpdate(ctx, NULL, &dec_len, NULL, enc_dataB->length);
			/* specify any AAD */
			EVP_DecryptUpdate(ctx, NULL, &dec_len, aesParam->aes_ccm.aad->buffer, aesParam->aes_ccm.aad->length);
		}
		/* Decrypt plaintext, verify tag: can only be called once */
		rv = EVP_DecryptUpdate(ctx, dec_dataB->buffer, &dec_len, enc_dataB->buffer, enc_dataB->length);
#ifdef OPENSSL_APP_LOG
		/* Output decrypted block:if tag verify failed we get nothing */
		if (rv > 0) {
			printf("\nDecrypted text:\n");
			BIO_dump_fp(stdout, dec_dataB->buffer, dec_len);
		} else {
			printf("\nPlaintext void :tag verify failed.\n");
		}
#endif
		EVP_CIPHER_CTX_free(ctx);
	}
	return status;
}
#endif

/*! @brief Encrypt data with  OpenSSL
 * @params:
 * in: pl_dataB- plain data in sk_buffer form
 * in: plKey- plain Key in sk_buffer form
 * out: enc_dataB- Encrypted data buffer in sk_buffer form
 * in: aesParam- AES parameters used in encryption and decryption
 * return: success or failure
 */

uint32_t openSSL_Encryption(void *pldataB, uint32_t pldataB_length,
			    void *plKey, uint32_t plKey_length,
			    void *enc_dataB, uint32_t *enc_dataB_length,
			    uint32_t aes_mode, void *iv, uint32_t iv_length) {
	uint32_t status = 0;
	AES_KEY enc_key;
	int32_t enc_len;
	EVP_CIPHER_CTX *ctx_ccm;
	uint32_t nonce_len;
	uint32_t ccm_mac_len;
	uint32_t aad_len;
	void *ccm_mac_buf;
	void *nonce;
	void *aad_buffer;


	if (aes_mode == ALGO_CIPHER_CBC_NO_PAD) {
		if ((pldataB_length % AES_BLOCK_SIZE) != 0)
			return 1;//SK_BAD_INPUT_DATA_SZ;

		AES_set_encrypt_key(plKey, (plKey_length)*8, &enc_key);
		AES_cbc_encrypt((unsigned char *)(pldataB),
				enc_dataB, pldataB_length,
				&enc_key, iv,
				AES_ENCRYPT);
		/* encrypted buf length will be same as that of input buf len.
		 */
		*enc_dataB_length = pldataB_length;
	} else if (aes_mode == ALGO_CCM) {
		ctx_ccm = EVP_CIPHER_CTX_new();
		/* Set cipher type and mode */
		if (plKey_length == 24)
			EVP_EncryptInit_ex(ctx_ccm, EVP_aes_192_ccm(), NULL, NULL, NULL);
		else if (plKey_length == 32)
			EVP_EncryptInit_ex(ctx_ccm, EVP_aes_256_ccm(), NULL, NULL, NULL);
		else if (plKey_length == 16)
			EVP_EncryptInit_ex(ctx_ccm, EVP_aes_128_ccm(), NULL, NULL, NULL);

		/* Set nonce length if default 96 bits is not appropriate */
		EVP_CIPHER_CTX_ctrl(ctx_ccm, 0x9, nonce_len, NULL);
		/* Set tag length */
		EVP_CIPHER_CTX_ctrl(ctx_ccm, 0x11, ccm_mac_len, NULL);
		/* Initialise key and IV */
		EVP_EncryptInit_ex(ctx_ccm, NULL, NULL, plKey, nonce);
		if (aad_buffer != NULL) {
			/* Set plaintext length: only needed if AAD is used */
			EVP_EncryptUpdate(ctx_ccm, NULL, &enc_len, NULL, pldataB_length);
			/* Zero or one call to specify any AAD */
			EVP_EncryptUpdate(ctx_ccm, NULL, &enc_len, aad_buffer, aad_len);
		}
		/* Encrypt plaintext: can only be called once */
		EVP_EncryptUpdate(ctx_ccm, enc_dataB, &enc_len, pldataB, pldataB_length);
#ifdef OPENSSL_APP_LOG
		printf("\n openssl enc plain key:\n");
		BIO_dump_fp(stdout, plKey, plKey_length);
#endif
		/* Output encrypted block */
		EVP_EncryptFinal_ex(ctx_ccm, enc_dataB, &enc_len);
#ifdef OPENSSL_APP_LOG
		printf("\n openssl enc plain Data:\n");
		BIO_dump_fp(stdout, pldataB, pldataB_length);
		printf("\n openssl enc Cipher text:\n");
		BIO_dump_fp(stdout, enc_dataB, *enc_dataB_length);
#endif
		/* Get tag */
		EVP_CIPHER_CTX_ctrl(ctx_ccm, 0x10, ccm_mac_len, ccm_mac_buf);
#ifdef OPENSSL_APP_LOG
		printf("\n open enc SSL Mac:\n");
		BIO_dump_fp(stdout, aesParam->aes_ccm_mac_buf, ccm_mac_len);
#endif
		/* free context */
		EVP_CIPHER_CTX_free(ctx_ccm);
	}
	return status;
}

void print_rsa_key(RSA *rsa)
{
	if (!rsa) {
		printf("RSA key is NULL\n");
		return;
	}

	const BIGNUM * n = NULL, *e = NULL, *d = NULL;

	// Extract key components
	RSA_get0_key(rsa, &n, &e, &d);

	if (n) {
		char *n_hex = BN_bn2hex(n);

		printf("Modulus (n): %s\n", n_hex);
		OPENSSL_free(n_hex);
	} else {
		printf("Modulus (n): NULL\n");
	}

	if (e) {
		char *e_hex = BN_bn2hex(e);

		printf("Public Exponent (e): %s\n", e_hex);
		OPENSSL_free(e_hex);
	} else {
		printf("Public Exponent (e): NULL\n");
	}

	if (d) {
		char *d_hex = BN_bn2hex(d);

		printf("Private Exponent (d): %s\n", d_hex);
		OPENSSL_free(d_hex);
	} else {
		printf("Private Exponent (d): NULL\n");
	}
}

EVP_PKEY *create_RSA_key(uint8_t *modulus, size_t modulus_size,
			 uint8_t *priv_exp, size_t priv_exp_size)
{
	EVP_PKEY *pkey = NULL;
	// Load RSA key from modulus and exponent
	BIGNUM *n = BN_bin2bn(modulus, modulus_size, NULL);
	BIGNUM *e = BN_new(); BN_set_word(e, RSA_F4);
	BIGNUM *d = BN_bin2bn(priv_exp, priv_exp_size, NULL);

	RSA *rsa = RSA_new();

	if (!n || !e || !d || !rsa) {
		printf("Error creating BIGNUMs or RSA structure\n");
		return NULL;
	}

	RSA_set0_key(rsa, n, e, d);

	pkey = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(pkey, rsa);

	return pkey;
}

void delete_RSA_key(EVP_PKEY *pkey)
{
	EVP_PKEY_free(pkey);
}

void print_openSSL_error(void)
{
	ERR_load_crypto_strings();
	unsigned long err_code;

	// Print all errors in the OpenSSL error queue
	while ((err_code = ERR_get_error()) != 0) {
		char err_msg[256];

		ERR_error_string_n(err_code, err_msg, sizeof(err_msg));
		printf("OpenSSL Error: %s\n", err_msg);
	}

	ERR_free_strings();
}

int8_t openSSL_RSA_encryption(uint8_t *plaintext, size_t plaintext_len,
			      uint8_t *ciphertext, size_t ciphertext_len,
			      EVP_PKEY *pkey)
{
	EVP_PKEY_CTX *ctx = NULL;
	uint8_t err = -1;

	// Encryption
	ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (!ctx || EVP_PKEY_encrypt_init(ctx) <= 0) {
		print_openSSL_error();
		goto cleanup;
	}

	// Set OAEP padding
	EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
#ifdef DEBUG
	//EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());

	// Determine buffer size
	if (EVP_PKEY_encrypt(ctx, NULL, &ciphertext_len, plaintext, plaintext_len) <= 0) {
		print_openSSL_error();
		goto cleanup;
	}
#endif
	if (!ciphertext ||
	    EVP_PKEY_encrypt(ctx, ciphertext, &ciphertext_len,
			     plaintext, plaintext_len) <= 0) {
		print_openSSL_error();
		goto cleanup;
	}

	err = 0;

cleanup:
	EVP_PKEY_CTX_free(ctx);

	return err;
}

int8_t openSSL_RSA_decryption(uint8_t *decrypted, size_t decrypted_len,
			      uint8_t *ciphertext, size_t ciphertext_len,
			      EVP_PKEY *pkey)
{
	EVP_PKEY_CTX *ctx = NULL;
	uint8_t err = -1;

	ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (!ctx || EVP_PKEY_decrypt_init(ctx) <= 0) {
		print_openSSL_error();
		goto cleanup;
	}

	EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
#ifdef DEBUG
//	EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());

	if (EVP_PKEY_decrypt(ctx, NULL, &decrypted_len,
			     ciphertext, ciphertext_len) <= 0) {
		print_openSSL_error();
		goto cleanup;
	}

	printf("Decrypted data length: %zu\n", decrypted_len);
#endif
	if (!decrypted ||
	    EVP_PKEY_decrypt(ctx, decrypted, &decrypted_len,
			     ciphertext, ciphertext_len) <= 0) {
		print_openSSL_error();
		goto cleanup;
	}

	err = 0;

cleanup:
	EVP_PKEY_CTX_free(ctx);

	return err;
}
