/*
 * Copyright 2019-2022 NXP
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


#ifndef PLAT_UTILS_H
#define PLAT_UTILS_H

#include "sab_msg_def.h"
#include "plat_os_abs.h"

typedef enum {
	NOT_SUPPORTED,
	ROM_MSG,
	SAB_MSG,
	MAX_MSG_TYPE,
} msg_type_t;

void plat_build_cmd_msg_hdr(struct sab_mu_hdr *hdr, msg_type_t msg_type,
			uint8_t cmd, uint32_t len, uint32_t mu_type);
void plat_build_rsp_msg_hdr(struct sab_mu_hdr *hdr, msg_type_t msg_type,
			uint8_t cmd, uint32_t len, uint32_t mu_type);

void plat_fill_cmd_msg_hdr(struct sab_mu_hdr *hdr, uint8_t cmd, uint32_t len, uint32_t mu_type);

void plat_fill_rsp_msg_hdr(struct sab_mu_hdr *hdr, uint8_t cmd, uint32_t len, uint32_t mu_type);

int32_t plat_send_msg_and_get_resp(struct plat_os_abs_hdl *phdl, uint32_t *cmd, uint32_t cmd_len, uint32_t *rsp, uint32_t rsp_len);

int32_t plat_send_msg_and_rcv_resp(struct plat_os_abs_hdl *phdl,
								uint32_t *cmd,
								uint32_t cmd_len,
								uint32_t *rsp,
								uint32_t *rsp_len);

uint32_t plat_compute_msg_crc(uint32_t *msg, uint32_t msg_len);
uint32_t plat_add_msg_crc(uint32_t *msg, uint32_t msg_len);
uint8_t plat_validate_msg_crc(uint32_t *msg, uint32_t msg_len);

#endif
