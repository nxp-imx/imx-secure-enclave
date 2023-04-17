// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2019-2023 NXP
 */

#ifndef SAB_MESSAGING_H
#define SAB_MESSAGING_H

#include "plat_os_abs.h"

/* Session */
uint32_t sab_open_session_command (struct plat_os_abs_hdl *phdl, uint32_t *session_handle, uint32_t mu_type, uint8_t mu_id, uint8_t interrupt_idx, uint8_t tz, uint8_t did, uint8_t priority,uint8_t operating_mode);
// should be kept aligned with flags definition in hsm API
#define SAB_OPEN_SESSION_PRIORITY_LOW       (0x00U)
#define SAB_OPEN_SESSION_PRIORITY_HIGH      (0x01U)

#define SAB_OPEN_SESSION_FIPS_MODE_MASK     (1u << 0)
#define SAB_OPEN_SESSION_EXCLUSIVE_MASK     (1u << 1)
#define SAB_OPEN_SESSION_LOW_LATENCY_MASK   (1u << 3)
#define SAB_OPEN_SESSION_NO_KEY_STORE_MASK  (1u << 4)


uint32_t sab_close_session_command (struct plat_os_abs_hdl *phdl, uint32_t session_handle, uint32_t mu_type);

uint32_t sab_get_shared_buffer(struct plat_os_abs_hdl *phdl, uint32_t session_handle, uint32_t mu_type);

/* Key store */
uint32_t sab_open_key_store_command(struct plat_os_abs_hdl *phdl, uint32_t session_handle, uint32_t *key_store_handle, uint32_t mu_type, uint32_t key_storage_identifier, uint32_t password, uint16_t max_updates, uint8_t flags, uint8_t min_mac_length);
#define KEY_STORE_OPEN_FLAGS_LOAD                   0x0u
#define KEY_STORE_OPEN_FLAGS_CREATE                 0x1u
#define KEY_STORE_OPEN_FLAGS_SHE                    0x2u
#define KEY_STORE_OPEN_FLAGS_SET_MAC_LEN            0x8u
#define KEY_STORE_OPEN_FLAGS_STRICT_OPERATION       0x80u


uint32_t sab_close_key_store(struct plat_os_abs_hdl *phdl, uint32_t key_store_handle, uint32_t mu_type);

/* random generation */
uint32_t sab_open_rng(struct plat_os_abs_hdl *phdl, uint32_t session_handle, uint32_t *rng_handle, uint32_t mu_type, uint8_t flags);
#define RNG_OPEN_FLAGS_DEFAULT          0x0u
#define RNG_OPEN_FLAGS_SHE              0x1u

uint32_t sab_close_rng(struct plat_os_abs_hdl *phdl, uint32_t rng_handle, uint32_t mu_type);

/* NVM storage */
uint32_t sab_open_storage_command(struct plat_os_abs_hdl *phdl, uint32_t session_handle, uint32_t *storage_handle, uint32_t mu_type, uint8_t flags);
uint32_t sab_close_storage_command(struct plat_os_abs_hdl *phdl, uint32_t storage_handle, uint32_t mu_type);
uint32_t sab_get_info(struct plat_os_abs_hdl *phdl, uint32_t session_handle, uint32_t mu_type, uint32_t *user_sab_id, uint8_t *chip_unique_id, uint16_t *chip_monotonic_counter, uint16_t *chip_life_cycle, uint32_t *version, uint32_t *version_ext, uint8_t *fips_mode);

/* MAC */
uint32_t sab_open_mac(struct plat_os_abs_hdl *phdl, uint32_t key_store_handle, uint32_t *mac_handle, uint32_t mu_type, uint8_t flags);
uint32_t sab_close_mac(struct plat_os_abs_hdl *phdl, uint32_t mac_handle, uint32_t mu_type);

/* SM2 ECES DEC */
uint32_t sab_open_sm2_eces(struct plat_os_abs_hdl *phdl, uint32_t key_store_handle, uint32_t *sm2_eces_handle, uint32_t mu_type, uint8_t flags);
uint32_t sab_close_sm2_eces(struct plat_os_abs_hdl *phdl, uint32_t sm2_eces_handle, uint32_t mu_type); 

uint32_t get_lib_version(void);
void set_phy_addr_to_words(uint32_t *lsb, uint32_t *msb, uint64_t phy_addr);
#endif
