// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#ifndef TEST_COMMON_TV_H
#define TEST_COMMON_TV_H

#include "test_utils_tv.h"

#ifdef PSA_COMPLIANT
#define DEFAULT_TV_DIR  "/usr/share/se/test_vectors/psa/"
#else
#define DEFAULT_TV_DIR  "/usr/share/se/test_vectors/non_psa/"
#endif
#define DEFAULT_TV_FEXTN ".tv"
#define DEFAULT_TV_PKF_FNAME "tv_keys_perist.pk"
#define DEFAULT_TV_PKF_PATH "/var/lib/se/persistent/"
#define DEFAULT_TV_PKF_FPATH (DEFAULT_TV_PKF_PATH DEFAULT_TV_PKF_FNAME)

void generate_key_test_tv(hsm_hdl_t key_store_hdl, FILE *fp, char *line, uint8_t
			  *tests_passed, uint8_t *tests_failed,
			  uint8_t *tests_invalid, uint8_t *tests_total);
void cipher_test_tv(hsm_hdl_t key_store_hdl, FILE *fp, char *line,
		    uint8_t *tests_passed, uint8_t *tests_failed,
		    uint8_t *tests_invalid, uint8_t *tests_total);
void mac_test_tv(hsm_hdl_t key_store_hdl, FILE *fp, char *line, uint8_t *tests_passed,
		 uint8_t *tests_failed, uint8_t *tests_invalid, uint8_t *tests_total);
void sign_verify_test_tv(hsm_hdl_t key_store_hdl, FILE *fp, char *line,
			 uint8_t *tests_passed, uint8_t *tests_failed,
			 uint8_t *tests_invalid, uint8_t *tests_total);
void hash_test_tv(FILE *fp, char *line, uint8_t *tests_passed, uint8_t *tests_failed,
		  uint8_t *tests_invalid, uint8_t *tests_total);
void data_storage_test_tv(hsm_hdl_t key_store_hdl, FILE *fp, char *line,
			  uint8_t *tests_passed, uint8_t *tests_failed,
			  uint8_t *tests_invalid, uint8_t *tests_total);
#endif
