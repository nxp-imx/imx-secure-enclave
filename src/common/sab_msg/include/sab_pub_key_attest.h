// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SAB_PUB_KEY_ATTEST_H
#define SAB_PUB_KEY_ATTEST_H

#include <stdint.h>

#include "sab_msg_def.h"

struct sab_cmd_pub_key_attest_msg {
	struct sab_mu_hdr hdr;
	uint32_t sig_gen_hdl;
	uint32_t key_identifier;
	uint32_t key_attestation_id;
	uint32_t sign_algo;
	uint32_t auth_challenge_addr;
	uint32_t auth_challenge_size;
	uint32_t certificate_addr;
	uint32_t certificate_size;
	uint32_t crc;
};

struct sab_cmd_pub_key_attest_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
	uint32_t output_certificate_size;
};

uint32_t prepare_msg_pub_key_attest(void *phdl,
				    void *cmd_buf, void *rsp_buf,
				    uint32_t *cmd_msg_sz,
				    uint32_t *rsp_msg_sz,
				    uint32_t msg_hdl,
				    void *args);

uint32_t proc_msg_rsp_pub_key_attest(void *rsp_buf, void *args);
#endif
