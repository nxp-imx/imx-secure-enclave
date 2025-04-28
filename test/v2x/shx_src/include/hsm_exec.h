// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#ifndef __hsm_exec_h__
#define __hsm_exec_h__

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hsm_api.h"

#define USE_SSL   // When removing, also need to remove -lssl reference from Makefile

#define MAX_SIGNATURE    3000
#define MAX_KEY_ID       102800
#define MAX_CIPHER       6
#define MAX_MAC          6
#define MAX_VCT          10
#define MAX_DATA_STORAGE 10
#define MAX_AUTH_ENC     6
#define MAX_RNG          1000
#define MAX_GET_Z        100

#define BAD_VAL       0xBADBAD
#define BAD_ADDR      0xBADBAD

#define BAD_0         0xBAD0  // to test address = 0x0
#define BAD_1         0xBAD1  // to test bad address = 0xBADBAD
#define BAD_2         0xBAD2  // to test good address with bad value

typedef struct {
	uint32_t key_id;
	uint32_t key_group;
} test_keyid_t;

// Struct to save test datas
typedef struct {
	//struct she_storage_context *storage_ctx;
	hsm_hdl_t hdl[20];
	// key id;
	uint32_t *key_id[MAX_KEY_ID];
	// key_group;
	uint32_t  key_group[MAX_KEY_ID];
	//indicate if key is stored in the file in case of save_key
	uint8_t idx_key[MAX_KEY_ID];
	// pub key;
	uint32_t pub_key_size[MAX_KEY_ID];
	uint8_t *pub_key_address[MAX_KEY_ID];
	// signature address;
	uint8_t *signature_address[MAX_SIGNATURE];
	uint32_t signature_size[MAX_SIGNATURE];
	// Cipher Data
	uint8_t *cipher_ptr[MAX_CIPHER];
	uint32_t cipher_size[MAX_CIPHER];
	// MAC Data
	uint8_t *mac_ptr[MAX_MAC];
	uint32_t mac_size[MAX_MAC];
	// input VCT
	uint32_t vct_size[MAX_VCT];
	uint8_t *vct_address[MAX_VCT];
	// data storage
	uint8_t *data_address[MAX_DATA_STORAGE];
	uint16_t data_id[MAX_DATA_STORAGE];
	uint32_t data_size[MAX_DATA_STORAGE];
	// auth enc
	uint8_t *auth_enc_ptr[MAX_AUTH_ENC];
	uint32_t auth_enc_size[MAX_AUTH_ENC];
	// rng
	uint8_t *rng_addr[MAX_RNG];
	uint32_t rng_size[MAX_RNG];
	// sm2 get Z
	uint8_t *sm2_get_z_addr[MAX_GET_Z];
	uint32_t sm2_get_z_size[MAX_GET_Z];
	pthread_t tid;
	FILE *fp;
	test_keyid_t  *data;
	int cmd_prio;
	int inst;
	int operating_mode;
	char cmd_name[32];
} hsm_test_struct_t;

struct test_entry_t {
	const char *name;
	uint32_t (*func)(hsm_test_struct_t *testCtx, FILE *fp);
};

#define HSM_TEST_COUNT 78
uint32_t save_key(hsm_test_struct_t *testCtx, FILE *fp);
uint32_t load_key(hsm_test_struct_t *testCtx, FILE *fp);

extern struct test_entry_t tests[HSM_TEST_COUNT];

int hsm_exec_function(int i, FILE *fp, void *testCtx);
void *hsm_thread(void *arguments);

#endif  // __hsm_exec_h__
