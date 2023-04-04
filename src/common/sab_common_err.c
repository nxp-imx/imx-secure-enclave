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

#include "sab_common_err.h"
#include "sab_msg_def.h"
#include "plat_utils.h"

void sab_err_map(uint8_t sab_cmd, uint32_t rsp_code)
{
	struct sab_err_map_s *sab_err_map_ptr = NULL;
	uint8_t sab_err_str[256];
	uint8_t i = 0;

	sab_err_map_ptr = get_sab_err_str_map();

	if (rsp_code == SAB_SUCCESS_STATUS)
		return;

	for (i = 0; i < SAB_ERR_MAP_N; i++) {
		if (rsp_code == sab_err_map_ptr[i].sab_err) {
			if (sprintf(sab_err_str,
				    "SAB Error: SAB CMD [0x%x] Resp [0x%x] - %s.\n",
				    sab_cmd,
				    rsp_code,
				    sab_err_map_ptr[i].sab_err_str) < 0)
				se_warn("unable to write string array for mapped error\n");
			break;
		}
	}

	if (i == SAB_ERR_MAP_N) {
		if (sprintf(sab_err_str,
			    "SAB Error: SAB CMD [0x%x]  Resp [0x%x] - Unknown error code\n",
			    sab_cmd,
			    rsp_code) < 0)
			se_warn("unable to write string array for unknown error\n");
	}

	printf("\n%s\n", sab_err_str);
}

