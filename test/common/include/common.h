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

#ifndef COMMON_H
#define COMMON_H

#include "hsm_api.h"

hsm_err_t do_mac_test(hsm_hdl_t key_store_hdl, hsm_hdl_t key_mgmt_hdl);
hsm_err_t do_cipher_test(hsm_hdl_t key_store_hdl, hsm_hdl_t key_mgmt_hdl);
hsm_err_t hsm_mac_test(hsm_hdl_t key_store_hdl, hsm_hdl_t key_mgmt_hdl);
hsm_err_t do_rng_test(hsm_hdl_t hsm_session_hdl);
void data_storage_test(hsm_hdl_t key_store_hdl, int arg);
void hash_test(hsm_hdl_t hash_sess);
hsm_err_t do_hash_test(hsm_hdl_t hash_session_hdl);

void hsm_sign_verify_tests(hsm_hdl_t sess_hdl, hsm_hdl_t key_store_hdl,
			   uint32_t key_id,
			   uint8_t *signature_data, uint32_t sign_data_sz,
			   uint8_t *hash_data, uint32_t hash_data_sz,
			   uint8_t *pub_key, uint32_t pub_key_sz);
/* To fetch the global session handle
 * opened as part of the test run
 */
hsm_hdl_t get_hsm_session_hdl(void);

/* To send the commmand line
 * input to any test.
 */
int get_cmdline_arg(void);

#endif
