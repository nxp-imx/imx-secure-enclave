/*
 * Copyright 2022-2023 NXP
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

#ifndef HSM_KEYS_H
#define HSM_KEYS_H

#include <stdint.h>

#include "internal/hsm_common_def.h"

#define IV_LENGTH		12

#define HSM_KEY_OP_SUCCESS	0
#define HSM_KEY_OP_FAIL		0xFFFFFFFF

typedef uint32_t hsm_key_usage_t;
#define HSM_KEY_USAGE_EXPORT		((hsm_key_usage_t) (1u << 0))
#define HSM_KEY_USAGE_ENCRYPT		((hsm_key_usage_t) (1u << 8))
#define HSM_KEY_USAGE_DECRYPT		((hsm_key_usage_t) (1u << 9))
#define HSM_KEY_USAGE_SIGN_MSG		((hsm_key_usage_t) (1u << 10))
#define HSM_KEY_USAGE_VERIFY_MSG	((hsm_key_usage_t) (1u << 11))
#define HSM_KEY_USAGE_SIGN_HASH		((hsm_key_usage_t) (1u << 12))
#define HSM_KEY_USAGE_VERIFY_HASH	((hsm_key_usage_t) (1u << 13))
#define HSM_KEY_USAGE_DERIVE		((hsm_key_usage_t) (1u << 14))

/* SE stands for Secure Enclave.
 */
typedef enum {
	HSM_SE_KEY_STORAGE = 0x00000100,
} hsm_storage_loc_t;

typedef enum {
	HSM_VOLATILE_STORAGE = 0x0,
	HSM_PERSISTENT_STORAGE = 0x1,
	HSM_VOLT_PERM_STORAGE = 0x80,
	HSM_PERS_PERM_STORAGE = 0x81,
} hsm_storage_persist_lvl_t;

typedef enum {
	HSM_SE_KEY_STORAGE_VOLATILE = HSM_SE_KEY_STORAGE | HSM_VOLATILE_STORAGE,
	HSM_SE_KEY_STORAGE_PERSISTENT = HSM_SE_KEY_STORAGE | HSM_PERSISTENT_STORAGE,
	HSM_SE_KEY_STORAGE_VOLT_PERM = HSM_SE_KEY_STORAGE | HSM_VOLT_PERM_STORAGE,
	HSM_SE_KEY_STORAGE_PERS_PERM = HSM_SE_KEY_STORAGE | HSM_PERS_PERM_STORAGE,
} hsm_key_lifetime_t;

typedef enum {
	HSM_PUBKEY_TYPE_RSA		= 0x4001,
	HSM_PUBKEY_TYPE_ECC_BP_R1	= 0x4130,
	HSM_PUBKEY_TYPE_ECC_NIST	= 0x4112,
	HSM_PUBKEY_TYPE_ECC_BP_T1	= 0xC180,
} hsm_pubkey_type_t;

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

typedef struct {
	uint8_t iv[IV_LENGTH];
	uint8_t *key;
	uint32_t tag;
} kek_enc_key_hdr_t;

//!< Permitted algorithm attribute (PSA values):
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
	PERMITTED_ALGO_ECB_NO_PADDING	= ALGO_CIPHER_ECB_NO_PAD,
	PERMITTED_ALGO_CBC_NO_PADDING	= ALGO_CIPHER_CBC_NO_PAD,
	PERMITTED_ALGO_CCM		= ALGO_CCM,
	PERMITTED_ALGO_GCM		= ALGO_GCM,
	PERMITTED_ALGO_ECDSA_SHA224	= ALGO_ECDSA_SHA224,
	PERMITTED_ALGO_ECDSA_SHA256	= ALGO_ECDSA_SHA256,
	PERMITTED_ALGO_ECDSA_SHA384	= ALGO_ECDSA_SHA384,
	PERMITTED_ALGO_ECDSA_SHA512	= ALGO_ECDSA_SHA512,
	PERMITTED_ALGO_HMAC_KDF_SHA256	= ALGO_HMAC_KDF_SHA256,
	PERMITTED_ALGO_ALL_CIPHER	= ALGO_CIPHER_ALL,
	PERMITTED_ALGO_ALL_AEAD		= ALGO_ALL_AEAD,
	PERMITTED_ALGO_OTH_KEK_CBC	= ALGO_CIPHER_KEK_CBC,
} hsm_permitted_algo_t;

//!< Permitted key lifecycle:
typedef enum {
	HSM_KEY_LIFECYCLE_OPEN		= 0x1,
	HSM_KEY_LIFECYCLE_CLOSED	= 0x2,
	HSM_KEY_LIFECYCLE_CLOSED_LOCKED	= 0x4,
} hsm_key_lifecycle_t;

typedef uint16_t hsm_key_group_t;

typedef uint16_t hsm_key_info_t;
/* HSM key-info flags */

//!< Persistent keys are stored in the external NVM.
//   The entire key group is written in the NVM at the next STRICT operation.
#define HSM_KEY_INFO_PERSISTENT \
		((hsm_key_info_t)(0u << 1))

//!< When set, the key is permanent (write locked). Once created, it will not
//   be possible to update or delete the key anymore. Transient keys will be
//   anyway deleted after a PoR or when the corresponding key store service flow
//   is closed. This bit can never be reset.
#define HSM_KEY_INFO_PERMANENT \
		((hsm_key_info_t)(1u << 0))

//!< Transient keys are deleted when the corresponding key store service flow is
//   closed or after a PoR. Transient keys cannot be in the same key group than
//   persistent keys.
#define HSM_KEY_INFO_TRANSIENT \
		((hsm_key_info_t)(1u << 1))

//!< When set, the key is considered as a master key.
//   Only master keys can be used as input of key derivation functions
//   (i.e butterfly key expansion).
#define HSM_KEY_INFO_MASTER \
		((hsm_key_info_t)(1u << 2))

//!< When set, the key is considered as a key encryption key. KEK keys can only
//   be used to wrap and import other keys into the key store, all other
//   operation are not allowed. Only keys imported in the key store through the
//   hsm_mange_key API can get this attribute.
#define HSM_KEY_INFO_KEK \
		((hsm_key_info_t)(1u << 3))

#endif
