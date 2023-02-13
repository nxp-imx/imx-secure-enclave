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

#ifndef TEST_COMMON_TV_H
#define TEST_COMMON_TV_H

#include "test_utils_tv.h"

#define DEFAULT_TV_FNAME "test_vectors.tv"
#define DEFAULT_TV_FPATH "/usr/share/se/test_vectors/" DEFAULT_TV_FNAME

void key_management(uint32_t key_op, hsm_hdl_t key_mgmt_hdl,
				uint32_t *key_id, hsm_key_group_t key_group,
				hsm_key_type_t key_type);
void generate_key_test_tv(hsm_hdl_t key_store_hdl, FILE *fp, char *line);
void cipher_test_tv(hsm_hdl_t key_store_hdl, FILE *fp, char *line);
void mac_test_tv(hsm_hdl_t key_store_hdl, FILE *fp, char *line);
void sign_verify_test_tv(hsm_hdl_t key_store_hdl, FILE *fp, char *line);
void hash_test_tv(FILE *fp, char *line);
void data_storage_test_tv(hsm_hdl_t key_store_hdl, FILE *fp, char *line);

#endif
