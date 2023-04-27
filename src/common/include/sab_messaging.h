// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2019-2023 NXP
 */

#ifndef SAB_MESSAGING_H
#define SAB_MESSAGING_H

#include "plat_os_abs.h"

uint32_t sab_get_info(struct plat_os_abs_hdl *phdl,
		      uint32_t session_handle,
		      uint32_t mu_type,
		      uint32_t *user_sab_id,
		      uint8_t *chip_unique_id,
		      uint16_t *chip_monotonic_counter,
		      uint16_t *chip_life_cycle,
		      uint32_t *version,
		      uint32_t *version_ext,
		      uint8_t *fips_mode);

uint32_t get_lib_version(void);
void set_phy_addr_to_words(uint32_t *lsb, uint32_t *msb, uint64_t phy_addr);
#endif
