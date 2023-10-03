// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SAB_IMPORT_PUB_KEY_H
#define SAB_IMPORT_PUB_KEY_H

#include "sab_msg_def.h"

struct sab_import_pub_key_msg {
	struct sab_mu_hdr hdr;
	uint32_t sig_ver_hdl;
	uint32_t key_addr;
	uint16_t key_size;
	uint8_t key_type;
	uint8_t flags;
};

struct sab_import_pub_key_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
	uint32_t key_ref;
};

uint32_t prepare_msg_import_pub_key(void *phdl,
				    void *cmd_buf, void *rsp_buf,
				    uint32_t *cmd_msg_sz,
				    uint32_t *rsp_msg_sz,
				    uint32_t msg_hdl,
				    void *args);

uint32_t proc_msg_rsp_import_pub_key(void *rsp_buf, void *args);
#endif
