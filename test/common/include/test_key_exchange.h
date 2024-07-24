// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#include <stdio.h>

#include "test_common.h"
#include "hsm_api.h"

#define TEST_KEYSTORE_ID 0xABCD

#define BITS_TO_BYTES(x) ((x) / 8u)

/* Derived Key Sizes: 256, 384 bits */
#define TEST_TLS1_3_DERIVED_MAX_KEY_SIZE BITS_TO_BYTES(384u)
#define TEST_HKDF_EXPAND_MAX_KEY_SIZE BITS_TO_BYTES(384u)

#define TEST_TLS1_3_HKDF_LABEL_KEY_EXPANSION_LEN_FIELD_SZ sizeof(uint16_t)
#define TEST_TLS1_3_HKDF_LABEL_LABEL_LEN_FIELD_SZ         sizeof(uint8_t)
#define TEST_TLS1_3_HKDF_LABEL_CTX_LEN_FIELD_SZ           sizeof(uint8_t)
#define TEST_TLS1_3_HKDF_LABEL_KEY_EXPANSION_MAX_LEN 255u
#define TEST_TLS1_3_LABEL_MAX_LEN       255u /* Reference RFC 8446 section 7.1 */
#define TEST_TLS1_3_CONTEXT_MAX_LEN     255u /* Reference RFC 8446 section 7.1 */
#define TEST_TLS1_3_HKDF_LABEL_CTX_MAX_LEN 64u /* SHA-512 */

#define TEST_TLS1_3_HKDF_LABEL_MAX_LEN \
	(TEST_TLS1_3_HKDF_LABEL_KEY_EXPANSION_LEN_FIELD_SZ +\
	 TEST_TLS1_3_HKDF_LABEL_LABEL_LEN_FIELD_SZ +\
	 TEST_TLS1_3_LABEL_MAX_LEN +\
	 TEST_TLS1_3_HKDF_LABEL_CTX_LEN_FIELD_SZ +\
	 TEST_TLS1_3_HKDF_LABEL_CTX_MAX_LEN)

/* TLS 1.2 RFC 5246: Section 6.3 & Section 8.1 */
static const char test_tls1_2_label_master_secret[] = "master secret";
static const char test_tls1_2_label_key_expansion[] = "key expansion";

/* TLS 1.3 labels */
static const char test_tls13_label_prefix[6] = "tls13 ";
static const char test_tls13_label_ext_binder[10] = "ext binder";
static const char test_tls13_label_client_handshake_traffic[12] = "c hs traffic";
static const char test_tls13_label_client_application_traffic[12] = "c ap traffic";

/**
 *  TLS 1.2 RFC 5246 ::
 *  label + seed: "master secret" + ClientHello.random + ServerHello.random
 */
static uint8_t test_tls1_2_ms_seed[] = {
	0x6d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x20, 0x73,
	0x65, 0x63, 0x72, 0x65, 0x74, 0x36, 0xc1, 0x29,
	0xd0, 0x1a, 0x32, 0x00, 0x89, 0x4b, 0x91, 0x79,
	0xfa, 0xac, 0x58, 0x9d, 0x98, 0x35, 0xd5, 0x87,
	0x75, 0xf9, 0xb5, 0xea, 0x35, 0x87, 0xcb, 0x8f,
	0xd0, 0x36, 0x4c, 0xae, 0x8c, 0xf6, 0xc9, 0x57,
	0x5e, 0xd7, 0xdd, 0xd7, 0x3e, 0x1f, 0x7d, 0x16,
	0xec, 0xa1, 0x15, 0x41, 0x58, 0x12, 0xa4, 0x3c,
	0x2b, 0x74, 0x7d, 0xaa, 0xaa, 0xe0, 0x43, 0xab,
	0xfb, 0x50, 0x05, 0x3f, 0xce,
};

/**
 *  TLS 1.2 RFC 5246 ::
 *  label + seed: "key expansion" + server_random + client_random
 */
static uint8_t test_tls1_2_kb_seed[] = {
	0x6b, 0x65, 0x79, 0x20, 0x65, 0x78, 0x70, 0x61,
	0x6e, 0x73, 0x69, 0x6f, 0x6e, 0xae, 0x6c, 0x80,
	0x6f, 0x8a, 0xd4, 0xd8, 0x07, 0x84, 0x54, 0x9d,
	0xff, 0x28, 0xa4, 0xb5, 0x8f, 0xd8, 0x37, 0x68,
	0x1a, 0x51, 0xd9, 0x28, 0xc3, 0xe3, 0x0e, 0xe5,
	0xff, 0x14, 0xf3, 0x98, 0x68, 0x62, 0xe1, 0xfd,
	0x91, 0xf2, 0x3f, 0x55, 0x8a, 0x60, 0x5f, 0x28,
	0x47, 0x8c, 0x58, 0xcf, 0x72, 0x63, 0x7b, 0x89,
	0x78, 0x4d, 0x95, 0x9d, 0xf7, 0xe9, 0x46, 0xd3,
	0xf0, 0x7b, 0xd1, 0xb6, 0x16,
};

/* ECC 256 Peer Public Key */
static uint8_t ecc_256_pub_key[64] = {
	0x07, 0x60, 0x64, 0xa3, 0xda, 0xa0, 0x05, 0xd0,
	0x14, 0xb9, 0x8a, 0x93, 0x1a, 0x48, 0xb2, 0xb5,
	0x54, 0xee, 0x1c, 0xe7, 0xa2, 0xaa, 0xc8, 0x96,
	0x50, 0xa5, 0xb6, 0x0f, 0x07, 0xc5, 0x0c, 0xd5,
	0x18, 0x92, 0x49, 0xd1, 0x5e, 0xa5, 0x55, 0x07,
	0x98, 0xb5, 0x84, 0xa8, 0xf8, 0xd7, 0x62, 0xb8,
	0xed, 0xf7, 0xb9, 0x3e, 0x2e, 0x2f, 0x0b, 0x7b,
	0xd2, 0xc6, 0x15, 0x4f, 0xa4, 0x6f, 0xf8, 0x91,
};

/* ECC 256 Peer Private Key */
static uint8_t ecc_256_priv_key[32] = {
	0x99, 0x8f, 0x6c, 0xcf, 0x3c, 0x1f, 0x03, 0xc9,
	0xa1, 0xd2, 0xd1, 0x4b, 0x84, 0x1b, 0xa8, 0x90,
	0xf3, 0x24, 0x04, 0xaa, 0xe7, 0xed, 0x82, 0x95,
	0x9a, 0x20, 0x4d, 0x64, 0xfc, 0x37, 0x77, 0x62,
};

static uint8_t test_msg[32] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
};

static uint8_t iv[16] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
};

/* Context/Transcript Random Hash Buffer */
static const unsigned char context_buffer[32] = {
	0x1b, 0x6a, 0x99, 0xe1, 0x5a, 0x4a, 0x57, 0x86,
	0x7d, 0x8a, 0x8f, 0xb1, 0x43, 0xf7, 0xfc, 0x7d,
	0xdd, 0x0a, 0x5a, 0xf2, 0x45, 0x5f, 0xfc, 0xba,
	0x0b, 0x77, 0xf7, 0x92, 0xa0, 0xf1, 0xbf, 0x20,
};

/* ECC 256 Public Key */
static uint8_t public_buffer[64] = {
	0xe4, 0x58, 0x39, 0x07, 0x39, 0xc8, 0x32, 0x6b,
	0x4a, 0x14, 0xb1, 0x7b, 0x1c, 0x94, 0xd8, 0xa6,
	0x91, 0x21, 0x84, 0x1f, 0x01, 0x78, 0xff, 0x51,
	0x7d, 0x51, 0x44, 0x51, 0x15, 0x64, 0xb6, 0xa3,
	0x78, 0x4e, 0x07, 0x1f, 0xb1, 0x8b, 0x71, 0xb4,
	0x62, 0x6b, 0xbe, 0x77, 0x39, 0x63, 0x25, 0xb7,
	0xd3, 0x34, 0xe0, 0x0d, 0x28, 0xe0, 0x55, 0x7a,
	0x05, 0xfd, 0x78, 0x42, 0x4d, 0x29, 0x68, 0xe8,
};

/* Random User Fixed Info */
static uint8_t user_fixed_info[32] = {
	0x1b, 0x6a, 0x99, 0xe1, 0x5a, 0x4a, 0x57, 0x86,
	0x7d, 0x8a, 0x8f, 0xb1, 0x43, 0xf7, 0xfc, 0x7d,
	0xdd, 0x0a, 0x5a, 0xf2, 0x45, 0x5f, 0xfc, 0xba,
	0x0b, 0x77, 0xf7, 0x92, 0xa0, 0xf1, 0xbf, 0x20,
};

/**
 * Structure describing the Key Exchange - Input Content (TLS 1.2 MS) member argument
 */
typedef struct {
	uint16_t ver;
	// Structure version. only 0x1 supported.
	uint16_t rsv;
	// Reserved
	uint32_t keystore_id;
	// Key store ID
	uint32_t tls1_2_algo;
	// TLS 1.2 algo to be used for Key Exchange process.
	uint32_t priv_key_id;
	// Private Key ID for ELE FW private key to be used with peer public key,
	// during premaster secret generation
	uint16_t derived_key_type;
	// Derived Key's type. Set to DERIVE by ELE, if key stored.
	uint16_t derived_key_bits_size;
	// Derived Key size in bits. Set to 384 by ELE.
	uint32_t derived_key_lifetime;
	// Derived Key Lifetime. Set to VOLATILE by ELE, if key stored.
	uint32_t derived_key_usage;
	// Derived Key Usage. Set to DERIVE by ELE, if key stored.
	uint32_t derived_key_permitted_algo;
	// Derived Key Permitted Algo. Set by ELE if key stored, depending on TLS 1.2
	// algorithm input. ELE sets Internal algorithm value that allows
	// the Master Secret to derive the TLS 1.2 key block and IVs.
	uint32_t derived_key_lifecycle;
	// Derived Key Lifeycle. Set to Current Lifecycle by ELE, if key stored.
	uint32_t derived_key_id;
	// Derived Key ID. Ignored by ELE.
	uint32_t reserved;
	// Reserved.
} in_content_tls1_2_master_secret_args_t;

/**
 * Structure describing the Key Exchange - Input Content (TLS 1.2 KB/IVs) member argument
 */
typedef struct {
	uint16_t ver;
	// Structure version. only 0x1 supported.
	uint16_t rsv;
	// Reserved
	uint32_t keystore_id;
	// Key store ID
	uint32_t tls1_2_algo;
	// TLS 1.2 algo to be used for Key Exchange process.
	uint32_t priv_key_id;
	// Private Key ID of Master Secret to be used to derive keys/IVs
	uint16_t derived_key_type;
	// Derived Key's type. Ignored by ELE.
	uint16_t ciphersuite_key_bits_size;
	// The client / server write key security size in bits.
	uint32_t derived_key_lifetime;
	// Derived Key Lifetime. Set to VOLATILE by ELE, if key stored.
	uint32_t derived_key_usage;
	// Ignored by ELE.
	uint32_t ciphersuite_algorithm;
	// permitted algorithm assigned to client / server write key
	// that defined the ciphersuite.
	uint32_t derived_key_lifecycle;
	// Derived Key Lifeycle. Set to Current Lifecycle by ELE, if key stored.
	uint32_t derived_key_id;
	// Derived Key ID. Ignored by ELE.
	uint32_t master_secret_len;
	// Master Secret length. Set to 48 bytes. 0 if used as stored secret.
	uint8_t *master_secret;
	// Master secret value, if master secret length is non-zero.
} in_content_tls1_2_key_block_args_t;

typedef in_content_tls1_2_key_block_args_t in_content_tls1_2_iv_args_t;

/**
 * Structure describing the Key Exchange - Input Content (TLS 1.3) member argument
 */
typedef struct {
	uint16_t ver;
	// Structure version. only 0x1 supported.
	uint16_t rsv;
	// Reserved
	uint32_t keystore_id;
	// Key store ID
	uint32_t tls1_3_algo;
	// TLS 1.3 algo to be used for Key Exchange process.
	uint32_t priv_key_id;
	// Private Key ID for ELE FW private key to be used for Key Agreement
	// with peer public key.
	uint16_t derived_key_type;
	// Derived Key's type, DERIVE. Not used if key exported
	uint16_t derived_key_bits_size;
	// Derived Key size in bits
	uint32_t derived_key_lifetime;
	// Derived Key Lifetime. VOLATILE hardcoded, if stored.
	uint32_t derived_key_usage;
	// Derived Key Usage. must be DERIVE. Ignored if key exported.
	uint32_t derived_key_permitted_algo;
	// Derived Key Permitted Algo. Ignored if key exported.
	uint32_t derived_key_lifecycle;
	// Derived Key Lifeycle. Hardcoded Current.
	uint32_t derived_key_id;
	// Derived Key ID. VOLATILE, ID chosen by FW, if stored.
	uint32_t psk_len;
	// Optional PSK buffer length.
} in_content_tls13_args_t;

/**
 * Structure describing the Key Exchange - Input Content (HKDF Expand) member argument
 */
typedef struct {
	uint16_t ver;
	// Structure version. only 0x1 supported.
	uint16_t rsv;
	// Reserved
	uint32_t keystore_id;
	// Key store ID
	uint32_t hkdf_expand_algo;
	// HKDF Expand algo to be used for Key Exchange process.
	uint32_t prk_id;
	// PRK ID for ELE FW private key to be used for Key Agreement
	// with peer public key.
	uint16_t derived_key_type;
	// Not used if key exported
	uint16_t derived_key_bits_size;
	// Derived Key size in bits
	uint32_t derived_key_lifetime;
	// Derived Key Lifetime.
	uint32_t derived_key_usage;
	// Derived Key Usage.
	uint32_t derived_key_permitted_algo;
	// Derived Key Permitted Algo.
	uint32_t derived_key_lifecycle;
	// Derived Key Lifeycle.
	uint32_t derived_key_id;
	// Derived Key ID
	uint32_t prk_len;
	// Optional PRK buffer length.
} in_content_hkdf_args_t;

/* Dump HEX buffer byte-by-byte */
void dump_hex(uint8_t buf[], uint32_t size);

/* The function calculates the HkdfLabel length */
static uint16_t tls13_hkdf_label_len_calc(uint8_t total_label_len,
					  uint8_t context_len);

/* The function prepares the HKDF label for TLS 1.3 following RFC 8446 section 7.1 */
void tls13_hkdf_label_encode(uint16_t length,
			     const unsigned char *label, uint8_t label_len,
			     const unsigned char *context, uint8_t context_len,
			     unsigned char *hkdf_label, uint16_t *hkdf_label_len);

/* Key Exchange - Signed Content test */
hsm_err_t key_exchange_test(hsm_hdl_t hsm_session_hdl,
			    hsm_hdl_t key_store_hdl,
			    hsm_hdl_t key_mgmt_hdl);

/**
 * Key Exchange - TLS 1.3 Secrets tests
 *      -"Early Secrets",
 *      -"Handshake Secrets",
 *      -"Master Secrets"
 */
void key_exchange_test_tls1_3(hsm_hdl_t key_mgmt_hdl);

/* Key Exchange - HKDF Expand tests */
void key_exchange_test_hkdf_expand(hsm_hdl_t key_mgmt_hdl);

/* Key Exchange - TLS 1.2 option tests */
void key_exchange_test_tls1_2(hsm_hdl_t key_store_hdl, hsm_hdl_t key_mgmt_hdl);
