// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023, 2025 NXP
 */


#include <stdint.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>

void HEXDUMP(unsigned char *buf, size_t sz);
int32_t compare_data(uint8_t *ori_data, uint8_t *dec_data, int32_t datalen);
void BUFF_DUMP(char *, unsigned char *, size_t);

uint32_t openSSL_Encryption(void *pldataB, uint32_t pldataB_length,
			    void *plKey, uint32_t plKey_length,
			    void *enc_dataB, uint32_t *enc_dataB_length,
			    uint32_t aes_mode, void *iv, uint32_t iv_length);
void print_rsa_key(RSA *rsa);
EVP_PKEY *create_RSA_key(uint8_t *modulus, size_t modulus_size,
			 uint8_t *priv_exp, size_t priv_exp_size);
void delete_RSA_key(EVP_PKEY *pkey);
int8_t openSSL_RSA_encryption(uint8_t *plaintext, size_t plaintext_len,
			      uint8_t *ciphertext, size_t ciphertext_len,
			      EVP_PKEY *pkey);
int8_t openSSL_RSA_decryption(uint8_t *decrypted, size_t decrypted_len,
			      uint8_t *ciphertext, size_t ciphertext_len,
			      EVP_PKEY *pkey);
