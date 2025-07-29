// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#ifndef CRRM_UTILS_H
#define CRRM_UTILS_H

#include "internal/hsm_utils.h"
#include "internal/hsm_handle.h"

#include <openssl/evp.h>

#include "crrm_api.h"

#define TIMER_INFO_SIZE			16
#define SIGNATURE_LENGTH		64
#define REQ_DATA_SIZE			(sizeof(request_data) + SIGNATURE_LENGTH)
#define ECC_PRIVATE_KEY_SIZE		32

hsm_err_t crrm_test_boot_mode(hsm_hdl_t crrm_hdl);
hsm_err_t crrm_test_get_AWDT_status(hsm_hdl_t crrm_hdl);
hsm_err_t crrm_test_get_nonce(hsm_hdl_t crrm_hdl);
hsm_err_t crrm_test_refresh_AWDT(hsm_hdl_t crrm_hdl, uint32_t timer_period);
hsm_err_t crrm_test_kill_timer(hsm_hdl_t crrm_hdl);
hsm_err_t crrm_test_recovery_install(hsm_hdl_t crrm_hdl);
EVP_PKEY *create_evp_key_from_array(const uint8_t *key_data, size_t key_len);
int sign_message_raw_rs(const uint8_t *msg, size_t msg_len, uint8_t raw_sig[64]);
void print_nonce_info(nonce_info *info);

#endif
