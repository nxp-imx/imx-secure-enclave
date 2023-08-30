// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SAB_EXPORT_PLAIN_KEY_H
#define SAB_EXPORT_PLAIN_KEY_H

#include <internal/she_export_plain_key.h>
#include "sab_msg_def.h"

/* Update key */
struct sab_she_export_plain_key_msg {
	struct sab_mu_hdr hdr;
	uint32_t utils_handle;
};

struct sab_she_export_plain_key_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
	uint32_t m1[M1_M3_M5_KEY_SIZE_IN_WORDS];
	uint32_t m2[M2_M4_KEY_SIZE_IN_WORDS];
	uint32_t m3[M1_M3_M5_KEY_SIZE_IN_WORDS];
	uint32_t m4[M2_M4_KEY_SIZE_IN_WORDS];
	uint32_t m5[M1_M3_M5_KEY_SIZE_IN_WORDS];
	uint32_t crc;
};

uint32_t prepare_msg_export_plain_key(void *phdl,
				      void *cmd_buf,
				      void *rsp_buf,
				      uint32_t *cmd_msg_sz,
				      uint32_t *rsp_msg_sz,
				      uint32_t msg_hdl,
				      void *args);

uint32_t proc_msg_rsp_export_plain_key(void *rsp_buf, void *args);

#endif
