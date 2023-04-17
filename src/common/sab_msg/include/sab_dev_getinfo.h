// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022 NXP
 */

#ifndef SAB_DEV_GETINFO_H
#define SAB_DEV_GETINFO_H

#include "sab_msg_def.h"

#define MAX_UID_SIZE                     (16)
#define DEV_GETINFO_ROM_PATCH_SHA_SZ     (32)
#define DEV_GETINFO_FW_SHA_SZ            (32)
#define DEV_GETINFO_OEM_SRKH_SZ          (64)

struct sab_cmd_dev_getinfo_msg {
	struct sab_mu_hdr hdr;
	uint32_t rsp_data_addr_hi;
	uint32_t rsp_data_addr_lo;
	uint16_t buf_sz;
	uint16_t reserved;
};

struct dev_info {
	uint8_t  cmd;
	uint8_t  ver;
	uint16_t length;
	uint16_t soc_id;
	uint16_t soc_rev;
	uint16_t lmda_val;
	uint8_t  ssm_state;
	uint8_t  reserved;
	uint8_t  uid[MAX_UID_SIZE];
	uint8_t  sha_rom_patch[DEV_GETINFO_ROM_PATCH_SHA_SZ];
	uint8_t  sha_fw[DEV_GETINFO_FW_SHA_SZ];
};

struct dev_addn_info {
	uint8_t  oem_srkh[DEV_GETINFO_OEM_SRKH_SZ];
	uint8_t  trng_state;
	uint8_t  csal_state;
	uint8_t  imem_state;
	uint8_t  reserved2;
};

struct sab_cmd_dev_getinfo_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
};

/* device info buffer is allocated
 * next to the response data buffer.
 */
struct sab_cmd_dev_getinfo_rsp_w_data {
	struct sab_cmd_dev_getinfo_rsp rsp;
	struct dev_info d_info;
	struct dev_addn_info d_addn_info;
};

uint32_t prepare_msg_dev_getinfo(void *phdl, void *cmd_buf, void *rsp_buf,
				 uint32_t *cmd_msg_sz, uint32_t *rsp_msg_sz,
				 uint32_t msg_hdl, void *args);

uint32_t proc_msg_rsp_dev_getinfo(void *rsp_buf, void *args);

#endif
