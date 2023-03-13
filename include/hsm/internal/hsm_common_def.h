/*
 * Copyright 2023 NXP
 *
 * NXP Confidential.
 * This software is owned or controlled by NXP and may only be used strictly
 * in accordance with the applicable license terms.  By expressly accepting
 * such terms or by downloading, installing, activating and/or otherwise using
 * the software, you are agreeing that you have read, and that you agree to
 * comply with and are bound by, such license terms.  If you do not agree to be
 * bound by the applicable license terms, then you may not retain, install,
 * activate or otherwise use the software.
 */
#ifndef HSM_COMMON_DEF_H
#define HSM_COMMON_DEF_H

typedef enum {
	ALGO_HASH_SHA224 = 0x02000008,
	ALGO_HASH_SHA256 = 0x02000009,
	ALGO_HASH_SHA384 = 0x0200000A,
	ALGO_HASH_SHA512 = 0x0200000B,
	ALGO_HASH_SM3    = 0x02000014,
} hsm_sha_algo_t;

typedef enum {
	ALGO_HMAC_SHA256 = 0x03800009,
	ALGO_HMAC_SHA384 = 0x0380000A,
	ALGO_CMAC	 = 0x03C00200,
} hsm_hmac_algo_t;

typedef enum {
	ALGO_CIPHER_CTR	         = 0x04C01000,
	ALGO_CIPHER_CFB	         = 0x04C01100,
	ALGO_CIPHER_ECB_NO_PAD	 = 0x04404400,
	ALGO_CIPHER_CBC_NO_PAD	 = 0x04404000,
	ALGO_CIPHER_ALL	         = 0x84C0FF00,
	ALGO_CIPHER_KEK_CBC      = 0x84404000,
} hsm_cipher_algo_t;

typedef enum {
		ALGO_CCM				= 0x05500100,
		ALGO_GCM				= 0x05500200,
		ALGO_ECDSA_SHA224		= 0x06000608,
		ALGO_ECDSA_SHA256		= 0x06000609,
		ALGO_ECDSA_SHA384		= 0x0600060A,
		ALGO_ECDSA_SHA512		= 0x0600060B,
		ALGO_HMAC_KDF_SHA256	= 0x08000109,
		ALGO_ALL_CIPHER			= 0x84C0FF00,
		ALGO_ALL_AEAD			= 0x8550FF00,
} hsm_algo_t;
#endif
