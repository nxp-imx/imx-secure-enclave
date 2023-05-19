// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#ifndef HSM_KEYS_H
#define HSM_KEYS_H

#include <stdint.h>

#include "internal/hsm_common_def.h"

#define IV_LENGTH		12

#define HSM_KEY_OP_SUCCESS	0
#define HSM_KEY_OP_FAIL		0xFFFFFFFF

/**
 *  @defgroup group3 Key management
 * @{
 */

/**
 * Bitmap indicating the cryptographic operations that key can execute
 */
typedef uint32_t hsm_key_usage_t;
/**
 * Bit indicating the permission to export the key
 */
#define HSM_KEY_USAGE_EXPORT		((hsm_key_usage_t) (1u << 0))
/**
 * Bit indicating the permission to encrypt a message with the key
 */
#define HSM_KEY_USAGE_ENCRYPT		((hsm_key_usage_t) (1u << 8))
/**
 * Bit indicating the permission to decrypt a message with the key
 */
#define HSM_KEY_USAGE_DECRYPT		((hsm_key_usage_t) (1u << 9))
/**
 * Bit indicating the permission to sign a message with the key
 */
#define HSM_KEY_USAGE_SIGN_MSG		((hsm_key_usage_t) (1u << 10))
/**
 * Bit indicating the permission to verify a message signature with the key
 */
#define HSM_KEY_USAGE_VERIFY_MSG	((hsm_key_usage_t) (1u << 11))
/**
 * Bit indicating the permission to sign a hashed message with the key
 */
#define HSM_KEY_USAGE_SIGN_HASH		((hsm_key_usage_t) (1u << 12))
/**
 * Bit indicating the permission to verify a hashed message signature with the key
 */
#define HSM_KEY_USAGE_VERIFY_HASH	((hsm_key_usage_t) (1u << 13))
/**
 * Bit indicating the permission to derive other keys from this key
 */
#define HSM_KEY_USAGE_DERIVE		((hsm_key_usage_t) (1u << 14))

/**
 * Enum Indicating the key location indicator.
 */
typedef enum {
	HSM_SE_KEY_STORAGE = 0x00000000,
} hsm_storage_loc_t;

/**
 * Enum Indicating the key persistent level indicator.
 */
typedef enum {
	HSM_VOLATILE_STORAGE = 0x0,
	HSM_PERSISTENT_STORAGE = 0x1,
	HSM_PERMANENT_STORAGE = 0xFF,
} hsm_storage_persist_lvl_t;

/**
 * Enum Indicating the key lifetime.
 */
typedef enum {
	HSM_SE_KEY_STORAGE_VOLATILE = HSM_SE_KEY_STORAGE | HSM_VOLATILE_STORAGE,
	HSM_SE_KEY_STORAGE_PERSISTENT = HSM_SE_KEY_STORAGE | HSM_PERSISTENT_STORAGE,
	HSM_SE_KEY_STORAGE_PERS_PERM = HSM_SE_KEY_STORAGE | HSM_PERMANENT_STORAGE,
} hsm_key_lifetime_t;

/**
 * Enum Indicating the public key type.
 */
typedef enum {
	HSM_PUBKEY_TYPE_RSA		= 0x4001,
	HSM_PUBKEY_TYPE_ECC_BP_R1	= 0x4130,
	HSM_PUBKEY_TYPE_ECC_NIST	= 0x4112,
	HSM_PUBKEY_TYPE_ECC_BP_T1	= 0xC180,
} hsm_pubkey_type_t;

/**
 * Enum Indicating the key type.
 */
typedef enum {
#ifdef PSA_COMPLIANT
	/* PSA Compliant key types.
	 */
	HSM_KEY_TYPE_HMAC                   = 0x1100,
	HSM_KEY_TYPE_AES                    = 0x2400,
	HSM_KEY_TYPE_SM4                    = 0x2405,
	HSM_KEY_TYPE_RSA                    = 0x7001,
	HSM_KEY_TYPE_ECC_BP_R1              = 0x7130,
	HSM_KEY_TYPE_ECC_NIST               = 0x7112,
#else
	/* NON-PSA Compliant key types.
	 */
	HSM_KEY_TYPE_ECDSA_NIST_P224          = 0x01,
	HSM_KEY_TYPE_ECDSA_NIST_P256          = 0x02,
	HSM_KEY_TYPE_ECDSA_NIST_P384          = 0x03,
	HSM_KEY_TYPE_ECDSA_NIST_P521          = 0x04,
	HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_224   = 0x12,
	HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_256   = 0x13,
	HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_320   = 0x14,
	HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_384   = 0x15,
	HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_512   = 0x16,
	HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_224   = 0x22,
	HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_256   = 0x23,
	HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_320   = 0x24,
	HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_384   = 0x25,
	HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_512   = 0x26,
	HSM_KEY_TYPE_AES_128                  = 0x30,
	HSM_KEY_TYPE_AES_192                  = 0x31,
	HSM_KEY_TYPE_AES_256                  = 0x32,
	HSM_KEY_TYPE_DSA_SM2_FP_256           = 0x42,
	HSM_KEY_TYPE_SM4_128                  = 0x50,
	HSM_KEY_TYPE_HMAC_224                 = 0x60,
	HSM_KEY_TYPE_HMAC_256                 = 0x61,
	HSM_KEY_TYPE_HMAC_384                 = 0x62,
	HSM_KEY_TYPE_HMAC_512                 = 0x63,
	HSM_KEY_TYPE_RSA_2048                 = 0x71,
	HSM_KEY_TYPE_RSA_4096                 = 0x73,
#endif
} hsm_key_type_t;

/**
 * Enum Indicating the key security size in bits.
 */
typedef enum {
	HSM_KEY_SIZE_HMAC_224		= 224,
	HSM_KEY_SIZE_HMAC_256		= 256,
	HSM_KEY_SIZE_HMAC_384		= 384,
	HSM_KEY_SIZE_HMAC_512		= 512,
	HSM_KEY_SIZE_AES_128		= 128,
	HSM_KEY_SIZE_AES_192		= 192,
	HSM_KEY_SIZE_AES_256		= 256,
	HSM_KEY_SIZE_SM4_128		= 128,
	HSM_KEY_SIZE_RSA_2048		= 2048,
	HSM_KEY_SIZE_RSA_3072		= 3072,
	HSM_KEY_SIZE_RSA_4096		= 4096,
	HSM_KEY_SIZE_ECC_BP_R1_224	= 224,
	HSM_KEY_SIZE_ECC_BP_R1_256	= 256,
	HSM_KEY_SIZE_ECC_BP_R1_320	= 320,
	HSM_KEY_SIZE_ECC_BP_R1_384	= 384,
	HSM_KEY_SIZE_ECC_BP_R1_512	= 512,
	HSM_KEY_SIZE_ECC_NIST_224	= 224,
	HSM_KEY_SIZE_ECC_NIST_256	= 256,
	HSM_KEY_SIZE_ECC_NIST_384	= 384,
	HSM_KEY_SIZE_ECC_NIST_521	= 521,
	HSM_KEY_SIZE_ECC_BP_T1_224	= 224,
	HSM_KEY_SIZE_ECC_BP_T1_256	= 256,
	HSM_KEY_SIZE_ECC_BP_T1_320	= 320,
	HSM_KEY_SIZE_ECC_BP_T1_384	= 384,
} hsm_bit_key_sz_t;

/**
 * Structure describing the encryption key header
 */
typedef struct {
	uint8_t iv[IV_LENGTH];
	uint8_t *key;
	uint32_t tag;
} kek_enc_key_hdr_t;

/**
 * Enum describing the permiteed algorithm
 */
typedef enum {
	PERMITTED_ALGO_SHA224	        = ALGO_HASH_SHA224,
	PERMITTED_ALGO_SHA256	        = ALGO_HASH_SHA256,
	PERMITTED_ALGO_SHA384	        = ALGO_HASH_SHA384,
	PERMITTED_ALGO_SHA512	        = ALGO_HASH_SHA512,
	PERMITTED_ALGO_SM3	        = ALGO_HASH_SM3,
	PERMITTED_ALGO_HMAC_SHA256	= ALGO_HMAC_SHA256,
	PERMITTED_ALGO_HMAC_SHA384	= ALGO_HMAC_SHA384,
	PERMITTED_ALGO_CMAC		= ALGO_CMAC,
	PERMITTED_ALGO_CTR		= ALGO_CIPHER_CTR,
	PERMITTED_ALGO_CFB		= ALGO_CIPHER_CFB,
	PERMITTED_ALGO_OFB		= ALGO_CIPHER_OFB,
	PERMITTED_ALGO_ECB_NO_PADDING	= ALGO_CIPHER_ECB_NO_PAD,
	PERMITTED_ALGO_CBC_NO_PADDING	= ALGO_CIPHER_CBC_NO_PAD,
	PERMITTED_ALGO_CCM		= ALGO_CCM,
	PERMITTED_ALGO_GCM		= ALGO_GCM,
	PERMITTED_ALGO_RSA_PKCS1_V15_SHA224 = ALGO_RSA_PKCS1_V15_SHA224,
	PERMITTED_ALGO_RSA_PKCS1_V15_SHA256 = ALGO_RSA_PKCS1_V15_SHA256,
	PERMITTED_ALGO_RSA_PKCS1_V15_SHA384 = ALGO_RSA_PKCS1_V15_SHA384,
	PERMITTED_ALGO_RSA_PKCS1_V15_SHA512 = ALGO_RSA_PKCS1_V15_SHA512,
	PERMITTED_ALGO_RSA_PKCS1_PSS_MGF1_SHA224 = ALGO_RSA_PKCS1_PSS_MGF1_SHA224,
	PERMITTED_ALGO_RSA_PKCS1_PSS_MGF1_SHA256 = ALGO_RSA_PKCS1_PSS_MGF1_SHA256,
	PERMITTED_ALGO_RSA_PKCS1_PSS_MGF1_SHA384 = ALGO_RSA_PKCS1_PSS_MGF1_SHA384,
	PERMITTED_ALGO_RSA_PKCS1_PSS_MGF1_SHA512 = ALGO_RSA_PKCS1_PSS_MGF1_SHA512,
	PERMITTED_ALGO_ECDSA_SHA224	= ALGO_ECDSA_SHA224,
	PERMITTED_ALGO_ECDSA_SHA256	= ALGO_ECDSA_SHA256,
	PERMITTED_ALGO_ECDSA_SHA384	= ALGO_ECDSA_SHA384,
	PERMITTED_ALGO_ECDSA_SHA512	= ALGO_ECDSA_SHA512,
	PERMITTED_ALGO_HMAC_KDF_SHA256	= ALGO_HMAC_KDF_SHA256,
	PERMITTED_ALGO_ALL_CIPHER	= ALGO_CIPHER_ALL,
	PERMITTED_ALGO_ALL_AEAD		= ALGO_ALL_AEAD,
	PERMITTED_ALGO_OTH_KEK_CBC	= ALGO_CIPHER_KEK_CBC,
} hsm_permitted_algo_t;

/**
 * Enum detailing Permitted key lifecycle
 */
typedef enum {
	HSM_KEY_LIFECYCLE_OPEN		= 0x1,
	HSM_KEY_LIFECYCLE_CLOSED	= 0x2,
	HSM_KEY_LIFECYCLE_CLOSED_LOCKED	= 0x4,
} hsm_key_lifecycle_t;

/**
 * Bit field indicating the key group
 */
typedef uint16_t hsm_key_group_t;

/**
 * Bit field indicating the key information
 */
typedef uint16_t hsm_key_info_t;

/**
 * Bit indicating persistent keys which are stored in the external NVM.
 * The entire key group is written in the NVM at the next STRICT operation.
 */
#define HSM_KEY_INFO_PERSISTENT \
		((hsm_key_info_t)(0u << 1))

/**
 * Bit indicating the key is permanent.
 * When set, the key is permanent (write locked). Once created, it will not
 * be possible to update or delete the key anymore. Transient keys will be
 * anyway deleted after a PoR or when the corresponding key store service flow
 * is closed. This bit can never be reset.
 */
#define HSM_KEY_INFO_PERMANENT \
		((hsm_key_info_t)(1u << 0))

/**
 * Bit indicating the key is transient.
 * Transient keys are deleted when the corresponding key store service flow is
 * closed or after a PoR. Transient keys cannot be in the same key group than
 * persistent keys.
 */
#define HSM_KEY_INFO_TRANSIENT \
		((hsm_key_info_t)(1u << 1))

/**
 * Bit indicating the key is master key.
 * When set, the key is considered as a master key.
 * Only master keys can be used as input of key derivation functions
 * (i.e butterfly key expansion).
 */
#define HSM_KEY_INFO_MASTER \
		((hsm_key_info_t)(1u << 2))

/**
 * Bit indicating the key is key encryption key
 * When set, the key is considered as a key encryption key. KEK keys can only
 * be used to wrap and import other keys into the key store, all other
 * operation are not allowed. Only keys imported in the key store through the
 * hsm_mange_key API can get this attribute.
 */
#define HSM_KEY_INFO_KEK \
		((hsm_key_info_t)(1u << 3))

/** @} end of key management service flow */
#endif
