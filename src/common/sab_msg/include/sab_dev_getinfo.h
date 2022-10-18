/*
 * Copyright 2022 NXP
 *
 * NXP Confidential.
 * This software is owned or controlled by NXP and may only be used strictly
 * in accordance with the applicable license terms.  By expressly accepting
 * such terms or by downloading, installing, activating and/or otherwise using
 * the software, you are agreeing that you have read, and that you agree to
 * comply with and are bound by, such license terms.  If you do not agree to be
 * bound by the applicable license terms, then you may not retain, install,
 * activate or otherwise use the software.
 */

#ifndef SAB_DEV_GETINFO_H
#define SAB_DEV_GETINFO_H

#include "sab_msg_def.h"

#define MAX_UID_SIZE               (04)
#define DEV_ATTEST_SIGN_SIZE       (96)
#define DEV_ATTEST_SHA_SIZE        (32)

struct sab_cmd_dev_getinfo_msg {
	struct sab_mu_hdr hdr;
	uint32_t rsp_data_addr_hi;
	uint32_t rsp_data_addr_lo;
	uint16_t buf_sz;
	uint16_t reserved;
};

struct dev_info {
	uint8_t cmd;
	uint8_t ver;
	uint16_t length;
	uint16_t soc_id;
	uint16_t soc_rev;
	uint16_t lmda_val;
	uint8_t  ssm_state;
	uint8_t  reserved;
	uint32_t uid[MAX_UID_SIZE];
	uint8_t  sha_rom_patch[DEV_ATTEST_SHA_SIZE];
	uint8_t  sha_fw[DEV_ATTEST_SHA_SIZE];
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
};

uint32_t prepare_msg_dev_getinfo(void *phdl, void *cmd_buf, void *rsp_buf,
				 uint32_t *cmd_msg_sz, uint32_t *rsp_msg_sz,
				 uint32_t msg_hdl, void *args);

uint32_t proc_msg_rsp_dev_getinfo(void *rsp_buf, void *args);

#endif
