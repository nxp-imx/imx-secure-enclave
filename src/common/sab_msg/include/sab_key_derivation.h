// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#ifndef SAB_KEY_DERIVATION_H
#define SAB_KEY_DERIVATION_H

#include <stdint.h>

#include "sab_msg_def.h"

struct sab_cmd_key_derivation_msg {
	struct sab_mu_hdr hdr;
	uint32_t key_management_handle;
	uint16_t flags;
	uint16_t reserved;
	uint32_t algorithm;
	uint32_t addr_msb;
	uint32_t key_store_args_addr;
	uint32_t key_store_args_size;
	uint32_t key_derivation_algo_args_addr;
	uint32_t key_derivation_algo_args_size;
	uint32_t crc;
};

struct sab_key_derivation_algo_hkdf_args_t {
	uint16_t vers;
	uint16_t rsv1;
	uint32_t ikm_addr;
	uint32_t ikm_size;
	uint32_t salt_addr;
	uint32_t salt_size;
	uint32_t fixed_info_addr;
	uint32_t fixed_info_size;
	uint32_t okm_addr;
	uint32_t okm_size;
	uint32_t rsv2;
};

struct sab_cmd_key_derivation_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
	uint32_t derived_key_id;
};

uint32_t prepare_msg_key_derivation(void *phdl,
				    void *cmd_buf,
				    void *rsp_buf,
				    uint32_t *cmd_msg_sz,
				    uint32_t *rsp_msg_sz,
				    uint32_t msg_hdl,
				    void *args);

uint32_t proc_msg_rsp_key_derivation(void *rsp_buf, void *args);
#endif
