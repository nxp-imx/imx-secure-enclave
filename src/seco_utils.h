/*
 * Copyright 2019 NXP
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


#ifndef SECO_UTILS_H
#define SECO_UTILS_H

#include "seco_sab_msg_def.h"
#include "seco_os_abs.h"

void seco_fill_cmd_msg_hdr(struct sab_mu_hdr *hdr, uint8_t cmd, uint32_t len, uint32_t mu_type);

void seco_fill_rsp_msg_hdr(struct sab_mu_hdr *hdr, uint8_t cmd, uint32_t len, uint32_t mu_type);

int32_t seco_send_msg_and_get_resp(struct seco_os_abs_hdl *phdl, uint32_t *cmd, uint32_t cmd_len, uint32_t *rsp, uint32_t rsp_len);

uint32_t seco_compute_msg_crc(uint32_t *msg, uint32_t msg_len);

#endif
