// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SAB_SIGN_PREPARE_H
#define SAB_SIGN_PREPARE_H

#include "sab_msg_def.h"

struct sab_prepare_signature_msg {
	struct sab_mu_hdr hdr;
	uint32_t sig_gen_hdl;
	uint8_t scheme_id;
	uint8_t flags;
	uint16_t reserved;
};

struct sab_prepare_signature_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
};

uint32_t prepare_msg_prep_signature(void *phdl,
				    void *cmd_buf, void *rsp_buf,
				    uint32_t *cmd_msg_sz,
				    uint32_t *rsp_msg_sz,
				    uint32_t msg_hdl,
				    void *args);

uint32_t proc_msg_rsp_prep_signature(void *rsp_buf, void *args);

#endif
