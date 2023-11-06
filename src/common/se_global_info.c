// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <stdio.h>
#include <string.h>

#include "sab_msg_def.h"
#include "common/global_info.h"
#include "internal/se_version.h"
#include "plat_utils.h"

/**
 * Global Information structure contain information about SoC and the Library.
 * It will be used globally to take platform specific decisions.
 */
struct global_info_s {
	bool is_populated;
	//!< to ensure global info is populated once.
	uint8_t ver;
	//!< Supported version of HSM APIs
	uint32_t soc_id;
	//!< SoC ID
	uint32_t soc_rev;
	//!< SoC Revision
	uint16_t lifecycle;
	//!< Device Lifecycle
	uint8_t fips_mode;
	//!< Fips mode
	uint8_t lib_newness_ver;
	//!< Secure Enclave Library Newness Version
	uint8_t lib_major_ver;
	//!< Secure Enclave Library Major Version
	uint8_t lib_minor_ver;
	//!< Secure Enclave Library Minor Version
	uint8_t nvm_newness_ver;
	//!< NVM Library Newness Version
	uint8_t nvm_major_ver;
	//!< NVM Library Major Version
	uint8_t nvm_minor_ver;
	//!< NVM Library Minor Version
	char lib_version[GINFO_LIB_VERSION_LEN];
	//!< Secure Enclave Library version string
	char nvm_version[GINFO_NVM_VERSION_LEN];
	//!< NVM version string
	char se_commit_id[GINFO_COMMIT_ID_SZ];
	//!< Secure Enclave Build Commit ID
};

/**
 * Global Information structure instance which will be populated and later be
 * used for getting the required platform or library details.
 */
static struct global_info_s global_info;

const char *get_soc_id_str(uint16_t soc_id)
{
	switch (soc_id) {
	case SOC_IMX8DXL:
		return "i.MX8DXL";
#ifdef PSA_COMPLIANT
	case SOC_IMX8ULP:
		return "i.MX8ULP";
	case SOC_IMX93:
		return "i.MX93";
#endif
	case SOC_IMX95:
		return "i.MX95";
	default:
		return "Unknown SoC ID";
	}
}

const char *get_soc_rev_str(uint16_t soc_rev)
{
	switch (soc_rev) {
	case SOC_REV_A0:
		return "A0";
	case SOC_REV_A1:
		return "A1";
	case SOC_REV_A2:
		return "A2";
	case SOC_REV_B0:
		return "B0";
	default:
		return "Unknown SoC Rev";
	}
}

const char *get_soc_lf_str(uint16_t lifecycle)
{
	switch (lifecycle) {
	case SOC_LF_CLOSED:
		return "Closed";
#ifdef PSA_COMPLIANT
	case SOC_LF_OPEN:
		return "Open";
	case SOC_LF_CLOSED_LOCKED:
		return "Closed and Locked";
#else
	case SOC_LF_FAB_DEFAULT:
		return "Default Fab Mode";
	case SOC_LF_FAB_MODE:
		return "Fab Mode";
	case SOC_LF_NO_NXP_SECRETS:
		return "No NXP Secrets";
	case SOC_LF_WITH_NXP_SECRETS:
		return "With NXP Secrets";
	case SOC_LF_SCU_FW_CLOSED:
		return "SCU FW Closed";
	case SOC_LF_SECO_FW_CLOSED:
		return "SECO FW Closed";
	case SOC_LF_CLOSED_WITH_NXP_FW:
		return "Closed with NXP FW";
	case SOC_LF_PARTIAL_FIELD_RET:
		return "Partial Field return";
	case SOC_LF_FIELD_RET:
		return "Field return";
	case SOC_LF_NO_RET:
		return "No Return";
#endif
	default:
		return "Unknown";
	}
}

void populate_global_info(uint32_t session_hdl)
{
	int len;
	op_get_info_args_t getinfo_args = {0};

	plat_os_abs_memset((uint8_t *)&global_info, 0, sizeof(global_info));
	se_get_soc_info(session_hdl, &global_info.soc_id, &global_info.soc_rev);
#ifdef PSA_COMPLIANT
	if (global_info.soc_id == SOC_IMX93 && global_info.soc_rev == SOC_REV_A1)
		global_info.ver = HSM_API_VERSION_2;
	else
		global_info.ver = HSM_API_VERSION_1;
#endif
	plat_os_abs_memset((uint8_t *)&getinfo_args, 0, sizeof(getinfo_args));
	se_get_info(session_hdl, &getinfo_args);

	global_info.lifecycle =	getinfo_args.chip_life_cycle;
	global_info.fips_mode =	getinfo_args.fips_mode;
	global_info.lib_newness_ver = LIB_NEWNESS_VER;
	global_info.lib_major_ver = LIB_MAJOR_VER;
	global_info.lib_minor_ver = LIB_MINOR_VER;
	global_info.nvm_newness_ver = NVM_NEWNESS_VER;
	global_info.nvm_major_ver = NVM_MAJOR_VER;
	global_info.nvm_minor_ver = NVM_MINOR_VER;
	//prepare Secure Enclave library version string
	len = snprintf(global_info.lib_version,
		       GINFO_LIB_VERSION_LEN,
		       "%u.%u.%u",
		       global_info.lib_newness_ver,
		       global_info.lib_major_ver,
		       global_info.lib_minor_ver);
	if (len < 0)
		se_err("Failed to get Secure Enclave Library version\n");

	//prepare NVM version string
	len = snprintf(global_info.nvm_version,
		       GINFO_NVM_VERSION_LEN,
		       "%u.%u.%u",
		       global_info.nvm_newness_ver,
		       global_info.nvm_major_ver,
		       global_info.nvm_minor_ver);
	if (len < 0)
		se_err("Failed to get NVM version\n");

	if (strlen(LIB_COMMIT_ID) == GINFO_COMMIT_ID_SZ)
		plat_os_abs_memcpy(global_info.se_commit_id,
				   LIB_COMMIT_ID,
				   GINFO_COMMIT_ID_SZ);

	global_info.is_populated = true;
}

bool is_global_info_populated(void)
{
	return global_info.is_populated;
}

#ifdef PSA_COMPLIANT
uint8_t hsm_get_dev_attest_api_ver(void)
{
	return global_info.ver;
}
#endif

uint32_t se_get_soc_id(void)
{
	return global_info.soc_id;
}

uint32_t se_get_soc_rev(void)
{
	return global_info.soc_rev;
}

uint16_t se_get_chip_lifecycle(void)
{
	return global_info.lifecycle;
}

uint8_t se_get_fips_mode(void)
{
	return global_info.fips_mode;
}

uint8_t se_get_lib_newness_ver(void)
{
	return global_info.lib_newness_ver;
}

uint8_t se_get_lib_major_ver(void)
{
	return global_info.lib_major_ver;
}

uint8_t se_get_lib_minor_ver(void)
{
	return global_info.lib_minor_ver;
}

uint8_t se_get_nvm_newness_ver(void)
{
	return global_info.nvm_newness_ver;
}

uint8_t se_get_nvm_major_ver(void)
{
	return global_info.nvm_major_ver;
}

uint8_t se_get_nvm_minor_ver(void)
{
	return global_info.nvm_minor_ver;
}

const char *se_get_lib_version(void)
{
	return global_info.lib_version;
}

const char *se_get_nvm_version(void)
{
	return global_info.nvm_version;
}

const char *se_get_commit_id(void)
{
	return global_info.se_commit_id;
}

void show_global_info(void)
{
	se_info("-------------------------------------------------------\n");
	se_info("Global Info:\n");
	se_info("-------------------------------------------------------\n");
	se_info("%s %s\n",
		get_soc_id_str(se_get_soc_id()),
		get_soc_rev_str(se_get_soc_rev()));
	se_info("%s Lifecycle\n", get_soc_lf_str(se_get_chip_lifecycle()));
	se_info("Fips Mode 0x%x\n", se_get_fips_mode());
	se_info("LIB Version %s\n", se_get_lib_version());
	se_info("NVM Version %s\n", se_get_nvm_version());
	se_info("Build ID %s\n", se_get_commit_id());
	se_info("-------------------------------------------------------\n");
}
