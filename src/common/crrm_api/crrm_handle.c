// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025-2026 NXP
 */

#include <stdio.h>

#include "internal/crrm_handle.h"

extern crrm_hdl_t session_hdl;

crrm_hdl_t get_session_handle(void)
{
	if ((se_get_soc_id() & SOC_MASK_IMX94) == SOC_IMX94 ||
	    se_get_soc_id() == SOC_IMX937 ||
	    se_get_soc_id() == SOC_IMX952)
		return session_hdl;

	printf("CRRM is not supported on %s\n", get_soc_id_str(se_get_soc_id()));
	return 0;
}
