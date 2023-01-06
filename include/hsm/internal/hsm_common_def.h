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
		ALGO_HMAC_SHA256		= 0x03800009,
		ALGO_HMAC_SHA384		= 0x0380000A,
		ALGO_CMAC				= 0x03C00200,
		ALGO_CTR				= 0x04C01000,
		ALGO_ECB_NO_PADDING		= 0x04404400,
		ALGO_CBC_NO_PADDING		= 0x04404000,
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
