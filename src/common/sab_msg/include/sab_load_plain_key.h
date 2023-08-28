// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SAB_LOAD_PLAIN_KEY_H
#define SAB_LOAD_PLAIN_KEY_H

#include <internal/she_key.h>
#include "sab_msg_def.h"

/* Update key */
struct sab_she_load_plain_key_msg {
	struct sab_mu_hdr hdr;
	uint32_t utils_handle;
	uint8_t key[SHE_KEY_SIZE_IN_BYTES];
	uint32_t crc;
};

struct sab_she_load_plain_key_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
};

uint32_t prepare_msg_load_plain_key(void *phdl,
				    void *cmd_buf, void *rsp_buf,
				    uint32_t *cmd_msg_sz,
				    uint32_t *rsp_msg_sz,
				    uint32_t msg_hdl,
				    void *args);

uint32_t proc_msg_rsp_load_plain_key(void *rsp_buf, void *args);

#endif
