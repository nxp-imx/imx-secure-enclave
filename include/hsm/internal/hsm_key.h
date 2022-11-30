/*
 * Copyright 2022 NXP
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

#define IV_LENGTH		12

#define HSM_KEY_OP_SUCCESS	0
#define HSM_KEY_OP_FAIL		0xFFFFFFFF

typedef uint32_t hsm_key_usage_t;
#define HSM_KEY_USAGE_EXPORT		((hsm_key_usage_t) (1u << 0))
#define HSM_KEY_USAGE_CLOSED		((hsm_key_usage_t) (1u << 4))
#define HSM_KEY_USAGE_ENCRYPT		((hsm_key_usage_t) (1u << 8))
#define HSM_KEY_USAGE_DECRYPT		((hsm_key_usage_t) (1u << 9))
#define HSM_KEY_USAGE_SIGN_MSG		((hsm_key_usage_t) (1u << 10))
#define HSM_KEY_USAGE_VERIFY_MSG	((hsm_key_usage_t) (1u << 11))
#define HSM_KEY_USAGE_SIGN_HASH		((hsm_key_usage_t) (1u << 12))
#define HSM_KEY_USAGE_VERIFY_HASH	((hsm_key_usage_t) (1u << 13))
#define HSM_KEY_USAGE_DERIVE		((hsm_key_usage_t) (1u << 14))

typedef enum {
	HSM_HW_INTERNAL_STORAGE = 0x00000000,
	HSM_HW_EXTERNAL_STORAGE = 0x80000000,
	HSM_SW_INTERNAL_STORAGE = 0x90000200,
	HSM_SW_EXTERNAL_STORAGE = 0x90000000,
} hsm_storage_loc_t;

typedef enum {
	HSM_VOLATILE_STORAGE = 0x0,
	HSM_PERSISTENT_STORAGE = 0x1,
	HSM_VOLT_PERM_STORAGE = 0x80,
	HSM_PERS_PERM_STORAGE = 0x81,
} hsm_storage_persist_lvl_t;

typedef enum {
	HSM_HW_INTERN_STORAGE_VOLATILE = HSM_HW_INTERNAL_STORAGE
						| HSM_VOLATILE_STORAGE,
	HSM_HW_INTERN_STORAGE_PERSISTENT = HSM_HW_INTERNAL_STORAGE
						| HSM_PERSISTENT_STORAGE,
	HSM_HW_INTERN_STORAGE_VOLT_PERM = HSM_HW_INTERNAL_STORAGE
						| HSM_VOLT_PERM_STORAGE,
	HSM_HW_INTERN_STORAGE_PERS_PERM = HSM_HW_INTERNAL_STORAGE
						| HSM_PERS_PERM_STORAGE,
	HSM_HW_EXTERN_STORAGE_PERSISTENT = HSM_HW_EXTERNAL_STORAGE
						| HSM_PERSISTENT_STORAGE,
	HSM_SW_INTERN_STORAGE_VOLATILE = HSM_SW_INTERNAL_STORAGE
						| HSM_VOLATILE_STORAGE,
	HSM_SW_INTERN_STORAGE_PERSISTENT = HSM_SW_INTERNAL_STORAGE
						| HSM_PERSISTENT_STORAGE,
	HSM_SW_INTERN_STORAGE_VOLT_PERM = HSM_SW_INTERNAL_STORAGE
						| HSM_VOLT_PERM_STORAGE,
	HSM_SW_INTERN_STORAGE_PERS_PERM = HSM_SW_INTERNAL_STORAGE
						| HSM_PERS_PERM_STORAGE,
	HSM_SW_EXTERN_STORAGE_PERSISTENT = HSM_SW_EXTERNAL_STORAGE
						| HSM_PERSISTENT_STORAGE,
} hsm_key_lifetime_t;

typedef enum {
	HSM_KEY_TYPE_HMAC	= 0x1100,
	HSM_KEY_TYPE_AES	= 0x2400,
	HSM_KEY_TYPE_SM4	= 0x2405,
	HSM_KEY_TYPE_RSA	= 0x7001,
	HSM_KEY_TYPE_ECC_BP_R1	= 0x7130,
	HSM_KEY_TYPE_ECC_NIST	= 0x7112,
	HSM_KEY_TYPE_ECC_BP_T1	= 0xF180,
} hsm_psa_key_type_t;

typedef enum {
	HSM_PUBKEY_TYPE_RSA		= 0x4001,
	HSM_PUBKEY_TYPE_ECC_BP_R1	= 0x4130,
	HSM_PUBKEY_TYPE_ECC_NIST	= 0x4112,
	HSM_PUBKEY_TYPE_ECC_BP_T1	= 0xC180,
} hsm_pubkey_type_t;

typedef uint8_t hsm_key_type_t;
#define HSM_KEY_TYPE_ECDSA_NIST_P224                        ((hsm_key_type_t)0x01u)
#define HSM_KEY_TYPE_ECDSA_NIST_P256                        ((hsm_key_type_t)0x02u)
#define HSM_KEY_TYPE_ECDSA_NIST_P384                        ((hsm_key_type_t)0x03u)
#define HSM_KEY_TYPE_ECDSA_NIST_P521                        ((hsm_key_type_t)0x04u)
#define HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_224                 ((hsm_key_type_t)0x12u)
#define HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_256                 ((hsm_key_type_t)0x13u)
#define HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_320                 ((hsm_key_type_t)0x14u)
#define HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_384                 ((hsm_key_type_t)0x15u)
#define HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_512                 ((hsm_key_type_t)0x16u)
#define HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_224                 ((hsm_key_type_t)0x22u)
#define HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_256                 ((hsm_key_type_t)0x23u)
#define HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_320                 ((hsm_key_type_t)0x24u)
#define HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_384                 ((hsm_key_type_t)0x25u)
#define HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_512                 ((hsm_key_type_t)0x26u)
#define HSM_KEY_TYPE_AES_128                                ((hsm_key_type_t)0x30u)
#define HSM_KEY_TYPE_AES_192                                ((hsm_key_type_t)0x31u)
#define HSM_KEY_TYPE_AES_256                                ((hsm_key_type_t)0x32u)
#define HSM_KEY_TYPE_DSA_SM2_FP_256                         ((hsm_key_type_t)0x42u)
#define HSM_KEY_TYPE_SM4_128                                ((hsm_key_type_t)0x50u)
#define HSM_KEY_TYPE_HMAC_224                               ((hsm_key_type_t)0x60u)
#define HSM_KEY_TYPE_HMAC_256                               ((hsm_key_type_t)0x61u)
#define HSM_KEY_TYPE_HMAC_384                               ((hsm_key_type_t)0x62u)
#define HSM_KEY_TYPE_HMAC_512                               ((hsm_key_type_t)0x63u)
#define HSM_KEY_TYPE_RSA_2048                               ((hsm_key_type_t)0x71u)
#define HSM_KEY_TYPE_RSA_4096                               ((hsm_key_type_t)0x73u)

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
	PERMITTED_ALGO_HMAC_SHA256			= 0x03800009,
	PERMITTED_ALGO_HMAC_SHA384			= 0x0380000A,
	PERMITTED_ALGO_CMAC				= 0x03C00200,
	PERMITTED_ALGO_CTR				= 0x04C01000,
	PERMITTED_ALGO_ECB_NO_PADDING			= 0x04404400,
	PERMITTED_ALGO_CBC_NO_PADDING			= 0x04404000,
	PERMITTED_ALGO_CCM				= 0x05500100,
	PERMITTED_ALGO_GCM				= 0x05500200,
	PERMITTED_ALGO_RSA_PKCS1_V15_SHA1		= 0x06000205,
	PERMITTED_ALGO_RSA_PKCS1_V15_SHA224		= 0x06000208,
	PERMITTED_ALGO_RSA_PKCS1_V15_SHA256		= 0x06000209,
	PERMITTED_ALGO_RSA_PKCS1_V15_SHA384		= 0x0600020A,
	PERMITTED_ALGO_RSA_PKCS1_V15_SHA512		= 0x0600020B,
	PERMITTED_ALGO_RSA_PKCS1_V15_ANY_HASH		= 0x060002FF,
	PERMITTED_ALGO_RSA_PKCS1_PSS_MGF1_SHA1		= 0x06000305,
	PERMITTED_ALGO_RSA_PKCS1_PSS_MGF1_SHA224	= 0x06000308,
	PERMITTED_ALGO_RSA_PKCS1_PSS_MGF1_SHA256	= 0x06000309,
	PERMITTED_ALGO_RSA_PKCS1_PSS_MGF1_SHA384	= 0x0600030A,
	PERMITTED_ALGO_RSA_PKCS1_PSS_MGF1_SHA512	= 0x0600030B,
	PERMITTED_ALGO_RSA_PKCS1_PSS_MGF1_ANY_HASH	= 0x060003FF,
	PERMITTED_ALGO_ECDSA_SHA224			= 0x06000608,
	PERMITTED_ALGO_ECDSA_SHA256			= 0x06000609,
	PERMITTED_ALGO_ECDSA_SHA384			= 0x0600060A,
	PERMITTED_ALGO_ECDSA_SHA512			= 0x0600060B,
	PERMITTED_ALGO_ECDSA_ANY_HASH			= 0x060006FF,
	PERMITTED_ALGO_HMAC_KDF_SHA256			= 0x08000109,
	PERMITTED_ALGO_TLS_1_2_PRF_SHA256		= 0x08000209,
	PERMITTED_ALGO_TLS_1_2_PRF_SHA384		= 0x0800020A,
	PERMITTED_ALGO_ALL_CIPHER			= 0x84C0FF00,
} hsm_permitted_algo_t;

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

uint32_t set_key_type_n_sz(hsm_key_type_t key_type,
			   hsm_bit_key_sz_t *key_sz,
			   hsm_psa_key_type_t *psa_key_type,
			   hsm_pubkey_type_t *pkey_type,
			   uint16_t *byte_key_size);
#endif
