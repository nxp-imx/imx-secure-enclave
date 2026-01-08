// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <stdio.h>
#include <stdint.h>

#include "hsm_api.h"
#include "test_common.h"

void test_gen_ele_key_blob(hsm_hdl_t sess_hdl)
{
#ifdef PSA_COMPLIANT
	printf("Testing GEN ELE KEY BLOB feature.\n");
#else
	printf("GEN ELE KEY BLOB feature is not supported on non-PSA.\n");
#endif
}
