// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#ifndef SAB_KEY_AGREEMENT_H
#define SAB_KEY_AGREEMENT_H

#include <stdint.h>

#include "sab_msg_def.h"

struct sab_cmd_key_agreement_msg {
	struct sab_mu_hdr hdr;
	uint32_t key_management_handle;
	uint16_t flags;
	uint16_t reserved;
	uint32_t algorithm;
	uint32_t addr_msb;
	uint32_t key_store_args_addr;
	uint32_t key_store_args_size;
	uint32_t key_agreement_algo_args_addr;
	uint32_t key_agreement_algo_args_size;
	uint32_t crc;
};

struct sab_key_agreement_algo_ecdh_args_t {
	uint16_t vers;
	uint16_t rsv1;
	uint32_t peer_pub_key_addr;
	uint32_t peer_pub_key_size;
	uint32_t priv_key_addr;
	uint32_t priv_key_size;
	uint32_t shared_secret_addr;
	uint32_t shared_secret_size;
	uint32_t rsv2;
};

struct sab_cmd_key_agreement_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
	uint32_t shared_secret_key_id;
};

uint32_t prepare_msg_key_agreement(void *phdl,
				   void *cmd_buf,
				   void *rsp_buf,
				   uint32_t *cmd_msg_sz,
				   uint32_t *rsp_msg_sz,
				   uint32_t msg_hdl,
				   void *args);

uint32_t proc_msg_rsp_key_agreement(void *rsp_buf, void *args);
#endif
