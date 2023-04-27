// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2019-2023 NXP
 */

#ifndef SAB_MESSAGING_H
#define SAB_MESSAGING_H

#include "plat_os_abs.h"

// should be kept aligned with flags definition in hsm API
#define SAB_OPEN_SESSION_PRIORITY_LOW       (0x00U)
#define SAB_OPEN_SESSION_PRIORITY_HIGH      (0x01U)
#define SAB_OPEN_SESSION_FIPS_MODE_MASK     (1u << 0)
#define SAB_OPEN_SESSION_EXCLUSIVE_MASK     (1u << 1)
#define SAB_OPEN_SESSION_LOW_LATENCY_MASK   (1u << 3)
#define SAB_OPEN_SESSION_NO_KEY_STORE_MASK  (1u << 4)

#define KEY_STORE_OPEN_FLAGS_LOAD                   0x0u
#define KEY_STORE_OPEN_FLAGS_CREATE                 0x1u
#define KEY_STORE_OPEN_FLAGS_SHE                    0x2u
#define KEY_STORE_OPEN_FLAGS_SET_MAC_LEN            0x8u
#define KEY_STORE_OPEN_FLAGS_STRICT_OPERATION       0x80u

#define RNG_OPEN_FLAGS_DEFAULT          0x0u
#define RNG_OPEN_FLAGS_SHE              0x1u

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
