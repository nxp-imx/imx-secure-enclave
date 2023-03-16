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

#ifndef TEST_UTILS_TV_H
#define TEST_UTILS_TV_H

#include "hsm_api.h"

/* Key Mgmt TV ID (in Test Vector) to Key Mgmt handle map */
struct key_mgmt_tv_id_map {
	uint32_t key_mgmt_tv_id;
	hsm_hdl_t key_mgmt_hdl;
};

/* Key TV ID to Key Identifier and other key details map */
struct key_tv_id_map {
	uint32_t key_tv_id;
	uint32_t key_mgmt_tv_id;
	uint32_t key_identifier;
	hsm_key_group_t key_group;
	hsm_key_type_t key_type;
};

void close_key_mgmt_srv(uint32_t key_mgmt_tv_id);
hsm_hdl_t get_key_mgmt_hdl(uint32_t key_mgmt_tv_id);
hsm_hdl_t open_key_mgmt_srv(hsm_hdl_t key_store_hdl, uint32_t key_mgmt_tv_id);

void delete_test_key(uint32_t key_tv_id);
uint32_t get_test_key_identifier(uint32_t key_tv_id);
void save_test_key(uint32_t key_tv_id, uint32_t key_identifier,
				uint32_t key_mgmt_tv_id, hsm_key_group_t key_group,
				hsm_key_type_t key_type);

uint32_t parse_param_value(char *param_value_token, char *param_name,
					uint8_t *input_ctr, uint8_t *invalid_read);

void parse_param_value_buffer(FILE *fp, uint8_t **dst, uint32_t size,
							char *param_name, uint8_t *input_ctr,
							uint8_t *invalid_read);

void print_buffer(uint8_t *buffer_ptr, uint32_t size);
void save_persistent_key(uint32_t key_tv_id, uint32_t key_identifier);
void load_persist_key_info(void);

#endif
