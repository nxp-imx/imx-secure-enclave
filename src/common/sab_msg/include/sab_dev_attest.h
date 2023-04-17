// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022 NXP
 */

#ifndef SAB_DEV_ATTEST_H
#define SAB_DEV_ATTEST_H

#include "sab_msg_def.h"
#include "sab_dev_getinfo.h"

#define DEV_ATTEST_SIGN_SIZE       (96)

struct sab_cmd_dev_attest_msg {
	struct sab_mu_hdr hdr;
	uint32_t rsp_data_addr_hi;
	uint32_t rsp_data_addr_lo;
	uint16_t buf_sz;
	uint16_t reserved;
	uint32_t nounce;
	uint32_t crc;
};

struct sab_cmd_dev_attest_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
};

struct sab_cmd_dev_attest_rsp_w_data {
	struct sab_cmd_dev_attest_rsp rsp;
	struct dev_info d_info;
	uint32_t nounce;
	uint8_t  signature[DEV_ATTEST_SIGN_SIZE];
};

uint32_t prepare_msg_dev_attest(void *phdl, void *cmd_buf, void *rsp_buf,
				uint32_t *cmd_msg_sz, uint32_t *rsp_msg_sz,
				uint32_t msg_hdl, void *args);

uint32_t proc_msg_rsp_dev_attest(void *rsp_buf, void *args);

#endif
