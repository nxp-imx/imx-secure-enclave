// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#include <stdio.h>

#include "test_common.h"
#include "hsm_api.h"

#ifdef PSA_COMPLIANT
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

/* TLS 1.3 labels */
static const char test_tls13_label_prefix[6] = "tls13 ";
static const char test_tls13_label_ext_binder[10] = "ext binder";
static const char test_tls13_label_client_handshake_traffic[12] = "c hs traffic";
static const char test_tls13_label_client_application_traffic[12] = "c ap traffic";

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
#endif
