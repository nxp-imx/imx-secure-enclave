// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2019-2023 NXP
 */

#include "sab_common_err.h"
#include "sab_messaging.h"

#include "plat_os_abs.h"

void set_phy_addr_to_words(uint32_t *lsb, uint32_t *msb, uint64_t phy_addr)
{
	if (lsb)
		*lsb = (uint32_t)(phy_addr & 0xFFFFFFFF);

	if (msb)
		*msb = (uint32_t)((phy_addr >> 32) & 0xFFFFFFFF);
}
