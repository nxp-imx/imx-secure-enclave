// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include <stdio.h>
#include <stdint.h>

#include "hsm_api.h"
#include "common.h"

void get_info(hsm_hdl_t sess_hdl)
{
#if HSM_GET_INFO
	op_get_info_args_t get_info_args = {0};
	hsm_err_t err;

	err = hsm_get_info(sess_hdl, &get_info_args);
	if (err != HSM_NO_ERROR)
		printf("hsm_get_info(FMW) failed err:0x%x\n", err);
	else {
		printf("hsm_get_info(FMW) message exchange is successful.\n\n");
		printf("User sab_id           : 0x%08x\n",
					get_info_args.user_sab_id);
		printf("Chip unique id        :");
		hexdump((uint32_t *)get_info_args.chip_unique_id,
			get_info_args.chip_unq_id_sz/sizeof(uint32_t));
		printf("Chip_monotonic_counter: 0x%04x\n",
					get_info_args.chip_monotonic_counter);
		printf("Chip life_cycle       : 0x%04x\n",
					get_info_args.chip_life_cycle);
		printf("Version               : 0x%08x\n",
					get_info_args.version);
		printf("Version-ext           : 0x%08x\n",
					get_info_args.version_ext);
		printf("FIPS Mode             : 0x%02x\n",
					get_info_args.fips_mode);
	}
#endif
}

void dev_get_info(hsm_hdl_t sess_hdl)
{
#if HSM_DEV_GETINFO
	op_dev_getinfo_args_t dev_getinfo_args = {0};
	hsm_err_t err;

	err = hsm_dev_getinfo(sess_hdl, &dev_getinfo_args);
	if (err != HSM_NO_ERROR)
		printf("hsm_dev_getinfo(ROM) failed err:0x%x\n", err);
	else {
		printf("hsm_dev_getinfo(ROM) message exchange is successful.\n\n");
		printf("SoC ID = 0x%x\n", dev_getinfo_args.soc_id);
		printf("SoC Rev = 0x%x\n", dev_getinfo_args.soc_rev);
		printf("LMDA Val = 0x%x\n", dev_getinfo_args.lmda_val);
		printf("SSM State = 0x%x\n", dev_getinfo_args.ssm_state);
		printf("UID:");
		hexdump((uint32_t *)dev_getinfo_args.uid,
			dev_getinfo_args.uid_sz/sizeof(uint32_t));

		printf("ROM Patch SHA Digest:");
		hexdump((uint32_t *)dev_getinfo_args.sha_rom_patch,
			dev_getinfo_args.rom_patch_sha_sz/sizeof(uint32_t));

		printf("FW SHA Digest:");
		hexdump((uint32_t *)dev_getinfo_args.sha_fw,
			dev_getinfo_args.sha_fw_sz/sizeof(uint32_t));

		printf("FW OEM SRKH:");
		hexdump((uint32_t *)dev_getinfo_args.oem_srkh,
			dev_getinfo_args.oem_srkh_sz/sizeof(uint32_t));

		printf("IMEM state = 0x%x.\n", dev_getinfo_args.imem_state);
		printf("CSAL state = 0x%x.\n", dev_getinfo_args.csal_state);
		printf("TRNG state = 0x%x.\n", dev_getinfo_args.trng_state);
	}
#endif
}

void get_device_info(hsm_hdl_t sess_hdl)
{
	printf("\n---------------------------------------------------\n");
	printf("Fetching Device Information.\n");
	printf("---------------------------------------------------\n");

	dev_get_info(sess_hdl);
	get_info(sess_hdl);

	printf("------------------------------------------------------\n");
}

