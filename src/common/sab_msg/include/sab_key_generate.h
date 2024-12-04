// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2024 NXP
 */

#ifndef SAB_KEY_GENERATE_H
#define SAB_KEY_GENERATE_H

#include <stdint.h>

#include "sab_msg_def.h"

struct sab_cmd_generate_key_msg {
	struct sab_mu_hdr hdr;
	uint32_t key_management_handle;
	/**
	 * key field represents:
	 *  - Identifier of the key
	 *  - Address of the key (Valid for PSA_COMPLIANT only)
	 */
	uint32_t key;
	uint16_t pub_key_sz;
#ifndef PSA_COMPLIANT
	uint8_t flags;
	uint8_t key_type;
	uint16_t key_group;
	uint16_t key_info;
#else
	uint16_t key_group;
	uint16_t key_type;
	uint16_t key_sz;
	uint32_t key_lifetime;
	uint32_t key_usage;
	uint32_t permitted_algo;
	uint32_t key_lifecycle;
	uint8_t flags;
	uint8_t rsv;
	uint16_t priv_key_sz;
#endif
	uint32_t pub_key_addr;
	uint32_t crc;
};

struct sab_cmd_generate_key_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
	uint32_t key_identifier;
#ifdef PSA_COMPLIANT
	uint16_t exp_pub_key_sz;
	uint16_t exp_priv_key_sz;
#endif
};

uint32_t prepare_msg_generatekey(void *phdl,
		void *cmd_buf, void *rsp_buf,
		uint32_t *cmd_msg_sz,
		uint32_t *rsp_msg_sz,
		uint32_t msg_hdl,
		void *args);

uint32_t proc_msg_rsp_generatekey(void *rsp_buf, void *args);
#endif
