// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SAB_KEY_UPDATE_H
#define SAB_KEY_UPDATE_H

#include <internal/she_key_update.h>
#include "sab_msg_def.h"

/* Update key */

#define M1_M3_M5_KEY_SIZE_IN_WORDS	(SHE_KEY_SIZE_IN_BYTES >> 2)
#define M2_M4_KEY_SIZE_IN_WORDS		(SHE_KEY_SIZE_IN_BYTES >> 1)

struct sab_she_key_update_msg {
	struct sab_mu_hdr hdr;
	uint32_t utils_handle;
	uint32_t key_id;
	uint32_t m1[M1_M3_M5_KEY_SIZE_IN_WORDS];
	uint32_t m2[M2_M4_KEY_SIZE_IN_WORDS];
	uint32_t m3[M1_M3_M5_KEY_SIZE_IN_WORDS];
	uint32_t crc;
};

struct sab_she_key_update_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
	uint32_t m4[M2_M4_KEY_SIZE_IN_WORDS];
	uint32_t m5[M1_M3_M5_KEY_SIZE_IN_WORDS];
	uint32_t crc;
};

/* Update key extension */

struct sab_she_key_update_ext_msg {
	struct sab_mu_hdr hdr;
	uint32_t utils_handle;
	uint32_t key_id;
	uint32_t m1[M1_M3_M5_KEY_SIZE_IN_WORDS];
	uint32_t m2[M2_M4_KEY_SIZE_IN_WORDS];
	uint32_t m3[M1_M3_M5_KEY_SIZE_IN_WORDS];
	uint8_t flags;
	uint8_t pad[3];
	uint32_t crc;
};

struct sab_she_key_update_ext_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
	uint32_t m4[M2_M4_KEY_SIZE_IN_WORDS];
	uint32_t m5[M1_M3_M5_KEY_SIZE_IN_WORDS];
	uint32_t crc;
};

uint32_t prepare_msg_key_update(void *phdl,
				void *cmd_buf, void *rsp_buf,
				uint32_t *cmd_msg_sz,
				uint32_t *rsp_msg_sz,
				uint32_t msg_hdl,
				void *args);

uint32_t proc_msg_rsp_key_update(void *rsp_buf, void *args);

uint32_t prepare_msg_key_update_ext(void *phdl,
				    void *cmd_buf, void *rsp_buf,
				    uint32_t *cmd_msg_sz,
				    uint32_t *rsp_msg_sz,
				    uint32_t msg_hdl,
				    void *args);

uint32_t proc_msg_rsp_key_update_ext(void *rsp_buf, void *args);

#endif
