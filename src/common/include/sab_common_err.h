/*
 * Copyright 2022-2023 NXP
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

#ifndef SAB_COMMON_ERR_H
#define SAB_COMMON_ERR_H

#include <stdio.h>
#include <stdint.h>

#define SAB_ERR_MAP_N 23
#define SAB_ERR_MAP_SZ 256

struct sab_err_map_s {
	uint32_t sab_err;
	char *sab_err_str;
};

struct sab_err_map_s *get_sab_err_str_map(void);
void sab_err_map(uint8_t sab_cmd, uint32_t rsp_code);
#endif
