// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
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
void sab_err_map(uint8_t msg_type, uint8_t sab_cmd, uint32_t rsp_code);
/**
 * prints error description for HSM library errors
 */
void sab_lib_err_map(uint8_t msg_id, uint32_t sab_lib_err);
/**
 * prints error description for library plat APIs errors
 */
void plat_lib_err_map(uint8_t msg_id, uint32_t plat_lib_err);
#endif
