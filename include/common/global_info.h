// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef GLOBAL_INFO_H
#define GLOBAL_INFO_H

#include "stdbool.h"
#include <stdint.h>

/**
 *  @defgroup group31 Global Info
 *  @{
 */

#include "get_info.h"
#include "internal/hsm_handle.h"

#define SOC_IMX8DXL 0xe
#define SOC_IMX8ULP 0x84d
#define SOC_IMX93   0x9300
#define SOC_IMX95   0x9500

#define SOC_REV_A0  0xa000
#define SOC_REV_A1  0xa100
#define SOC_REV_A2  0xa200
#define SOC_REV_B0  0xb000

#ifdef PSA_COMPLIANT
#define SOC_LF_OPEN                  0x1
#define SOC_LF_CLOSED                0x2
#define SOC_LF_CLOSED_LOCKED         0x4
#else
#define SOC_LF_FAB_DEFAULT           0x1
#define SOC_LF_FAB_MODE              0x2
#define SOC_LF_NO_NXP_SECRETS        0x4
#define SOC_LF_WITH_NXP_SECRETS      0x8
#define SOC_LF_SCU_FW_CLOSED         0x10
#define SOC_LF_SECO_FW_CLOSED        0x20
#define SOC_LF_CLOSED                0x40
#define SOC_LF_CLOSED_WITH_NXP_FW    0x80
#define SOC_LF_PARTIAL_FIELD_RET     0x100
#define SOC_LF_FIELD_RET             0x200
#define SOC_LF_NO_RET                0x400
#endif

#define GINFO_LIB_VERSION_LEN        16
#define GINFO_NVM_VERSION_LEN        16
#define GINFO_COMMIT_ID_SZ           40

#define HSM_API_VERSION_1    0x1
#define HSM_API_VERSION_2    0x2

/**
 * Populate the Global Info structure
 *
 * \param hsm_session_hdl identifying the session.
 */
void populate_global_info(hsm_hdl_t hsm_session_hdl);

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
 * Get SoC ID.
 */
uint32_t se_get_soc_id(void);

/**
 * Get SoC Revision.
 */
uint32_t se_get_soc_rev(void);

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
 * \param lifecycle value fetched from Global Info
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
void se_get_soc_info(uint32_t session_hdl, uint32_t *soc_id, uint32_t *soc_rev);
/** @} end of Global Info operation */
#endif
