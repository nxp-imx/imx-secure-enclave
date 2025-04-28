// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2025 NXP
 */

#ifndef GLOBAL_INFO_H
#define GLOBAL_INFO_H

#include "stdbool.h"
#include <stdint.h>

#include "get_info.h"

/**
 *  @defgroup group31 Global Info
 *  @{
 */
#ifndef PSA_COMPLIANT
#define SOC_IMX8QXP 0x2
#define SOC_IMX8DXL 0xe
#define IMX8DXL_DL1    0x1
#define IMX8DXL_DL2    0x2
#define IMX8DXL_DL3    0x4
#endif
#define SOC_IMX8ULP 0x84d
#define SOC_IMX91   0x9100
#define SOC_IMX93   0x9300
#define SOC_IMX95   0x9500
#define SOC_IMX943  0x9430
#define SOC_IMX952  0x9520

#define SOC_REV_A0  0xa000
#define SOC_REV_A1  0xa100
#define SOC_REV_A2  0xa200
#define SOC_REV_B0  0xb000
#define SOC_REV_C0  0xc000

#define GINFO_LIB_VERSION_LEN        16
#define GINFO_NVM_VERSION_LEN        16
#define GINFO_COMMIT_ID_SZ           40

#define HSM_API_VERSION_1    0x1
#define HSM_API_VERSION_2    0x2
#define HSM_API_VERSION_3    0x3

#ifdef PSA_COMPLIANT
#define SOC_LF_OPEN                  0x1
//!< Open chip lifecycle.
#define SOC_LF_CLOSED                0x2
//!< Closed chip lifecycle.
#define SOC_LF_CLOSED_LOCKED         0x4
//!< Closed Locked chip lifecycle.
#else
#define SOC_LF_FAB_DEFAULT             0x1
//!< Default fab mode chip lifecycle.
#define SOC_LF_FAB_MODE                0x2
//!< Fab mode chip lifecycle.
#define SOC_LF_NO_NXP_SECRETS          0x4
//!< No NXP secrets chip lifecycle.
#define SOC_LF_WITH_NXP_SECRETS        0x8
//!< With NXP secrets chip lifecycle.
#define SOC_LF_SCU_FW_CLOSED           0x10
//!< SCU FW Closed chip lifecycle.
#define SOC_LF_SECO_FW_CLOSED          0x20
//!< SECO FW Closed chip lifecycle.
#define SOC_LF_CLOSED                  0x40
//!< Closed chip lifecycle.
#define SOC_LF_CLOSED_WITH_NXP_FW      0x80
//!< Closed with NXP FW chip lifecycle.
#define SOC_LF_PARTIAL_FIELD_RET       0x100
//!< Partial Field Return chip lifecycle.
#define SOC_LF_FIELD_RET               0x200
//!< Field Return chip lifecycle.
#define SOC_LF_NO_RET                  0x400
//!< No Return chip lifecycle.
#define SOC_LF_BLANK                   0x1
//!< Blank chip lifecycle.
#define SOC_LF_DEFAULT_FAB             0x2
//!< Fab Default chip lifecycle.
#define SOC_LF_FAB                     0x4
//!< Fab chip lifecycle.
#define SOC_LF_NXP_PROVISIONED         0x8
//!< NXP Provisioned chip lifecycle.
#define SOC_LF_OEM_OPEN                0x10
//!< OEM Open chip lifecycle.
#define SOC_LF_OEM_SECURE_WORLD_CLOSED 0x20
//!< OEM Secure-World-Closed chip lifecycle.
#define SOC_LF_OEM_CLOSED              0x40
//!< OEM Closed chip lifecycle.
#define SOC_LF_OEM_LOCKED              0x80
//!< OEM Locked chip lifecycle.
#define SOC_LF_FIELD_RET_OEM           0x100
//!< Field Return OEM chip lifecycle.
#define SOC_LF_FIELD_RET_NXP           0x200
//!< Field Return NXP chip lifecycle.
#define SOC_LF_BRICKED                 0x400
//!< Bricked chip lifecycle.
#endif

/**
 * Populate the Global Info structure
 *
 * \param session_hdl identifying the session.
 */
void populate_global_info(uint32_t session_hdl);

/**
 * Print the Global Info of library
 */
void show_global_info(void);

/**
 * Get the status of Global Info, if populated or not.
 */
bool is_global_info_populated(void);

#ifdef PSA_COMPLIANT
/**
 * Get the version supported for Device Attestation.
 */
uint8_t hsm_get_dev_attest_api_ver(void);
#endif

/**
 * Get board type.
 */
uint8_t se_get_board_type(void);

/**
 * Get SoC ID.
 */
uint16_t se_get_soc_id(void);

/**
 * Get SoC Revision.
 */
uint16_t se_get_soc_rev(void);

/**
 * Get Chip-lifecycle.
 */
uint16_t se_get_chip_lifecycle(void);

/**
 * Get Fips mode.
 */
uint8_t se_get_fips_mode(void);

/**
 * Get library newness version.
 */
uint8_t se_get_lib_newness_ver(void);

/**
 * Get library major version.
 */
uint8_t se_get_lib_major_ver(void);

/**
 * Get library minor version.
 */
uint8_t se_get_lib_minor_ver(void);

/**
 * Get NVM newness version.
 */
uint8_t se_get_nvm_newness_ver(void);

/**
 * Get NVM major version.
 */
uint8_t se_get_nvm_major_ver(void);

/**
 * Get NVM minor version.
 */
uint8_t se_get_nvm_minor_ver(void);

/**
 * Get Build commit id.
 */
const char *se_get_commit_id(void);

/**
 * Get library version string.
 */
const char *se_get_lib_version(void);

/**
 * Get NVM version string.
 */
const char *se_get_nvm_version(void);

/**
 * Get the string representating board type
 *
 * \param board_type Board Type fetched from Global Info
 *
 * \return String represention of the board type
 */
const char *get_board_type_str(uint8_t board_type);

/**
 * Get the string representating SoC ID
 *
 * \param soc_id SoC ID fetched from Global Info
 *
 * \return String represention of the SoC ID
 */
const char *get_soc_id_str(uint16_t soc_id);

/**
 * Get the string representating SoC Revision
 *
 * \param soc_rev SoC Revision fetched from Global Info
 *
 * \return String represention of the SoC Revision
 */
const char *get_soc_rev_str(uint16_t soc_rev);

/**
 * Get the string representation of the Chip Lifecycle
 *
 * \param lifecycle value fetched from Global Info,
 * which will vary across SOCs
 *
 * \return a string represention of Lifecycle
 */
const char *get_soc_lf_str(uint16_t lifecycle);

/**
 * Get Info for Global Info setup
 */
void se_get_info(uint32_t session_hdl,
		 op_get_info_args_t *args);
/**
 * Get SoC Info for Global Info setup
 */
void se_get_soc_info(uint32_t session_hdl, uint16_t *soc_id,
		     uint16_t *soc_rev, uint8_t *board_type);

/**
 * Get Global Info flags
 */
uint32_t get_global_info_flags(void);

/**
 * Set Global Info flags
 */
void set_global_info_flags(uint32_t flags);
#ifndef PSA_COMPLIANT
/**
 *\addtogroup iMX8DXL
 * \ref group31
 *
 * i.MX8DXL Lifecycle
 * - \ref SOC_LF_FAB_DEFAULT
 * - \ref SOC_LF_FAB_MODE
 * - \ref SOC_LF_NO_NXP_SECRETS
 * - \ref SOC_LF_WITH_NXP_SECRETS
 * - \ref SOC_LF_SCU_FW_CLOSED
 * - \ref SOC_LF_SECO_FW_CLOSED
 * - \ref SOC_LF_CLOSED
 * - \ref SOC_LF_CLOSED_WITH_NXP_FW
 * - \ref SOC_LF_PARTIAL_FIELD_RET
 * - \ref SOC_LF_FIELD_RET
 * - \ref SOC_LF_NO_RET
 *
 */
/**
 *\addtogroup iMX95
 * \ref group31
 *
 * i.MX95 Lifecycle
 * - \ref SOC_LF_BLANK
 * - \ref SOC_LF_DEFAULT_FAB
 * - \ref SOC_LF_FAB
 * - \ref SOC_LF_NXP_PROVISIONED
 * - \ref SOC_LF_OEM_OPEN
 * - \ref SOC_LF_OEM_SECURE_WORLD_CLOSED
 * - \ref SOC_LF_OEM_CLOSED
 * - \ref SOC_LF_OEM_LOCKED
 * - \ref SOC_LF_FIELD_RET_OEM
 * - \ref SOC_LF_FIELD_RET_NXP
 * - \ref SOC_LF_BRICKED
 *
 */
#endif
/** @} end of Global Info operation */
#endif
