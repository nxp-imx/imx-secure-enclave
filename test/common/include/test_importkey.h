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

#ifndef TEST_IMPORT_KEY_H
#define TEST_IMPORT_KEY_H

#include <stdbool.h>

typedef enum {
	IMPORT_AGLO_RFC_399      = 0x1,
	IMPORT_ALGO_AES_CBC      = 0x2,
	IMPORT_ALGO_NONE         = 0x3,
} test_importkey_wrap_algo_t;

typedef enum {
	IMPORT_ALGO_CMAC  = 0x1,
	IMPORT_ALGO_ECDSA = 0x2,
} test_importkey_sign_algo_t;

struct tlv_data {
	uint8_t tag;
	uint8_t lv[];
};

#define MAX_IV_SIZE				0x20
#define MAX_KEY_BLOB_LEN			0xFF
#define TLV_LEN_GREATER_THAN_ONE_BYTE           0x80
#define SZ_OF_LEN_FIELD(len) \
	(len[0] > 128 ? (len[0] - TLV_LEN_GREATER_THAN_ONE_BYTE) : 1)

#define MAX_SIGN_LEN				80

#define E2GO_TLV_MAGIC_TAG			0x40
#define E2GO_TLV_KEY_ID_TAG			0x41
#define E2GO_TLV_KEY_ATTR_PERM_ALGO_TAG		0x42
#define E2GO_TLV_KEY_ATTR_USG_TAG		0x43
#define E2GO_TLV_KEY_ATTR_TYPE_TAG		0x44
#define E2GO_TLV_KEY_ATTR_BIT_SZ_TAG		0x45
#define E2GO_TLV_KEY_ATTR_LIFETIME_TAG		0x46

#define E2GO_TLV_IMPORTED_KEY_LC_TAG		0x47
#define E2GO_TLV_WRAP_KEY_ID_TAG		0x50
#define E2GO_TLV_WRAP_ALGO_TAG			0x51
#define E2GO_TLV_IV_TAG				0x52
#define E2GO_TLV_SIGNING_KEY_ID_TAG		0x53
#define E2GO_TLV_SIGNING_ALGO_TAG		0x54
#define E2GO_TLV_KEY_BLOB_TAG			0x55
#define E2GO_TLV_SIGNATURE_TAG			0x5E

#define E2GO_TLV_MAGIC_LEN                      0x0B
#define E2GO_TLV_KEY_ID_LEN                     0x04
#define E2GO_TLV_KEY_ATTR_PERM_ALGO_LEN		0x04
#define E2GO_TLV_KEY_ATTR_TYPE_LEN              0x02
#define E2GO_TLV_KEY_ATTR_USG_LEN		0x04
#define E2GO_TLV_KEY_ATTR_BIT_SZ_LEN		0x04
#define E2GO_TLV_KEY_ATTR_LIFETIME_LEN		0x04

#define E2GO_TLV_IMPORTED_KEY_LC_LEN		0x04
#define E2GO_TLV_WRAP_KEY_ID_LEN		0x04
#define E2GO_TLV_WRAP_ALGO_LEN			0x04
#define E2GO_TLV_IV_LEN				0x04
#define E2GO_TLV_SIGNING_KEY_ID_LEN             0x04
#define E2GO_TLV_SIGNING_ALGO_LEN		0x04

struct input_e2go_data {
	uint32_t key_id;
	uint32_t perm_algo_id;
	uint16_t key_type;
	uint32_t key_usage;
	uint32_t bit_key_sz;
	uint32_t key_lifetime;
	uint32_t import_key_lc;
	uint32_t wrap_key_id;
	uint32_t wrapping_algo;
	uint32_t iv_size;
	uint8_t  iv[MAX_IV_SIZE];
	uint32_t sign_key_id;
	uint32_t signing_algo;
	uint32_t key_blob_len;
	uint8_t  key_blob[MAX_KEY_BLOB_LEN];
};

#define WRAP_KEY_BUF_SZ                         128

struct test_import_key_data {
	bool is_set;
	uint32_t sign_key_id;
	uint32_t signing_algo;
	uint32_t wrap_key_id;
	uint32_t wrap_key_sz;
	uint8_t wrap_key_buf[WRAP_KEY_BUF_SZ];
};

int test_import_key(hsm_hdl_t sess_hdl,
		hsm_hdl_t key_store_hdl,
		hsm_hdl_t key_mgmt_hdl,
		uint32_t key_size,
		uint8_t *key_buf,
		op_import_key_args_t *args);
#endif
